"""보안 스캔 스텝 (Semgrep 정적 분석 + Claude AI 후처리 제안)."""

import asyncio
import logging
import os
import time
from datetime import datetime, timezone

from app.core.constants import Severity, StepStatus
from app.services.pipeline.step_executor import StepResult
from app.services.security.semgrep_service import CWE_SCAN_CONFIG, SemgrepService

logger = logging.getLogger(__name__)

_STEP_TYPE = "security_scan"


def _norm_rel(path: str) -> str:
    """경로를 매칭용으로 정규화한다 — 구분자를 '/'로 통일하고 선행 './'를 제거."""
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _build_changed_set(changed_files: list[str] | None) -> set[str] | None:
    """git diff 상대경로 목록을 정규화된 매칭 집합으로 변환한다.

    None 또는 모두 빈 문자열이면 None을 반환한다(= 전수 스캔).
    """
    if not changed_files:
        return None
    normalized = {_norm_rel(f) for f in changed_files if f and f.strip()}
    return normalized or None


def _finding_in_changed(file_path: str, repo_root_path: str, changed_set: set[str]) -> bool:
    """semgrep finding의 file_path(절대경로)가 변경 파일 집합에 속하는지 판정한다.

    file_path를 repo 루트 기준 상대경로로 정규화한 뒤 집합 멤버십을 확인한다.
    """
    if not file_path:
        return False
    rel = file_path
    if repo_root_path:
        try:
            rel = os.path.relpath(file_path, repo_root_path)
        except ValueError:
            # 다른 드라이브 등 relpath 불가 — 원본 경로로 폴백
            rel = file_path
    return _norm_rel(rel) in changed_set


def _cvss_to_severity(cvss_score: float | None) -> Severity:
    """
    CVSS v3.1 기준 점수를 Severity 열거형으로 변환한다.

    Critical : 9.0 ~ 10.0
    High     : 7.0 ~  8.9
    Medium   : 4.0 ~  6.9
    Low      : 0.1 ~  3.9
    Info     : 0.0 or None
    """
    if cvss_score is None:
        return Severity.INFO
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    if cvss_score > 0.0:
        return Severity.LOW
    return Severity.INFO


class SecurityScanStep:
    """멀티-CWE Semgrep 스캔으로 취약점을 탐지하는 파이프라인 스텝."""

    def __init__(self) -> None:
        self._semgrep_service = SemgrepService()

    async def run(
        self,
        repo_path: str,
        language: str,
        cve_list: list[dict],
        selected_cwe_ids: list[str] | None = None,
        cve_map: dict[str, list[dict]] | None = None,
        github_url: str = "",
        cve_service=None,
        db=None,
        changed_files: list[str] | None = None,
        repo_root_path: str = "",
    ) -> StepResult:
        """
        선택된 CWE에 맞는 Semgrep 룰로 저장소를 스캔하고 NVD CVE 정보를 매핑하여 반환한다.
        severity는 매핑된 CVE의 CVSS 점수(v3.1 기준)로 결정된다.

        Args:
            repo_path:         클론된 저장소 절대 경로.
            language:          감지된 언어 (로그 용도).
            cve_list:          (하위 호환) 평탄화된 CVE 목록.
            selected_cwe_ids:  분석할 CWE ID 목록. None이면 ["CWE-89"].
            cve_map:           CVEService.fetch_cves_by_cwe() 반환값.
                               None이면 cve_list로 {"CWE-89": cve_list} 구성.
            changed_files:     선택적 분석 — 이 파일들(repo 루트 기준 상대경로)에
                               해당하는 finding만 남긴다. None/빈 목록이면 전수 스캔.
            repo_root_path:    finding.file_path(절대경로)를 상대경로로 환원할 기준 루트.
                               미지정 시 repo_path를 사용한다.

        Returns:
            StepResult.
            metadata 키:
                - vulnerabilities (list[dict]): 정규화된 취약점 목록.
                - scan_log (str): semgrep 실행 로그 요약.
                - scan_mode (str): "selective" 또는 "full".
                - findings_before_filter (int): 선택적 분석 시 필터 전 finding 수.
        """
        started_at = datetime.now(tz=timezone.utc)

        _cwe_ids = selected_cwe_ids or ["CWE-89"]
        _fallback_cve_map: dict[str, list[dict]] = cve_map if cve_map is not None else {"CWE-89": cve_list}

        # 선택적 분석: 변경 파일 집합 구성 (None이면 전수 스캔)
        _changed_set = _build_changed_set(changed_files)
        _scan_mode = "selective" if _changed_set else "full"
        _filter_root = repo_root_path or repo_path
        _findings_before_filter = 0

        if not repo_path or not os.path.isdir(repo_path):
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                error=f"repo_path does not exist: {repo_path!r}",
            )

        logger.info(
            "SecurityScanStep: scan %s (language=%s, cwe=%s)",
            repo_path,
            language,
            _cwe_ids,
        )

        # CWE별 순차 처리: NVD조회 → Semgrep스캔 → 정규화 → AI분석
        # 각 CWE 타이밍에 NVD + Semgrep + AI 시간이 모두 포함됨
        cwe_scan_times: dict[str, float] = {}
        vulnerabilities: list[dict] = []
        ai_suggestion_count = 0
        all_flat_cves: list[dict] = []

        for cwe_id in _cwe_ids:
            _cwe_start = time.perf_counter()

            # 1. NVD CVE 조회
            if cve_service is not None:
                try:
                    cwe_cve_map = await cve_service.fetch_cves_by_cwe([cwe_id])
                    all_flat_cves.extend(cwe_cve_map.get(cwe_id, []))
                except Exception as exc:
                    logger.warning("SecurityScanStep: CVE fetch failed for %s: %s", cwe_id, exc)
                    cwe_cve_map = {}
            else:
                cwe_cve_map = {cwe_id: _fallback_cve_map.get(cwe_id, [])}

            # 2. Semgrep 스캔
            try:
                cwe_findings: list[dict] = await asyncio.to_thread(
                    self._semgrep_service.run_cwe_scan, repo_path, [cwe_id], cwe_cve_map
                )
            except Exception as exc:
                logger.warning("SecurityScanStep: semgrep failed for %s: %s", cwe_id, exc)
                cwe_scan_times[cwe_id] = time.perf_counter() - _cwe_start
                continue

            # 2.5 선택적 분석 — 변경 파일에 해당하는 finding만 남긴다 (정규화·AI 전 사전 필터)
            if _changed_set is not None:
                _findings_before_filter += len(cwe_findings)
                cwe_findings = [
                    f for f in cwe_findings
                    if _finding_in_changed(f.get("file_path", ""), _filter_root, _changed_set)
                ]

            # 3. Finding 정규화
            cwe_vulns: list[dict] = []
            for finding in cwe_findings:
                cvss_score: float | None = finding.get("cvss_score")
                severity_obj = _cvss_to_severity(cvss_score)
                cve_id_val = finding.get("cve_id")
                vuln = {
                    "rule_id":         finding.get("rule_id", ""),
                    "severity":        severity_obj.value,
                    "title":           finding.get("message", finding.get("rule_id", "Unknown")),
                    "description":     finding.get("cve_description") or finding.get("message", ""),
                    "file_path":       finding.get("file_path", ""),
                    "line_number":     finding.get("line_start"),
                    "cwe":             finding.get("cwe"),
                    "detected_cwe":    finding.get("detected_cwe"),
                    "cvss_score":      cvss_score,
                    "cvss_version":    finding.get("cvss_version"),
                    "code_snippet":    finding.get("code_snippet"),
                    "cve_description": finding.get("cve_description"),
                    "related_cve_ids": [cve_id_val] if cve_id_val else [],
                    "raw_output":      finding,
                }
                cwe_vulns.append(vuln)

            # 4. Claude AI: Semgrep 결과에 대한 후처리 제안 생성
            try:
                from app.integrations.gemini.client import analyze_findings as _ai_analyze
                analysis = await _ai_analyze(cwe_vulns, github_url or repo_path)
                if analysis:
                    for idx, item in analysis.items():
                        if 0 <= idx < len(cwe_vulns):
                            if not cwe_vulns[idx].get("suggestion"):
                                cwe_vulns[idx]["suggestion"] = item.get("suggestion", "")
                    ai_suggestion_count += len(analysis)
            except Exception as exc:
                logger.debug("SecurityScanStep: AI suggestion skipped for %s: %s", cwe_id, exc)

            cwe_scan_times[cwe_id] = time.perf_counter() - _cwe_start
            vulnerabilities.extend(cwe_vulns)

        # 5. CVE DB 저장 (semgrep 루프 완료 후 일괄)
        if cve_service is not None and db is not None and all_flat_cves:
            try:
                await cve_service.save_cves_to_db(all_flat_cves, db)
                flat_cve_ids = [c["cve_id"] for c in all_flat_cves if c.get("cve_id")]
                await cve_service.update_kev_flags(db, flat_cve_ids)
            except Exception as exc:
                logger.warning("SecurityScanStep: CVE DB save failed: %s", exc)

        finished_at = datetime.now(tz=timezone.utc)
        _elapsed = (finished_at - started_at).total_seconds()
        # 4.4 선택적 vs 전수 — 시간/탐지수 비교 로깅 (11월 실증 데이터 수집용)
        if _scan_mode == "selective":
            mode_note = (
                f"mode=selective files={len(_changed_set)} "
                f"findings={len(vulnerabilities)}/{_findings_before_filter}(kept/total)"
            )
        else:
            mode_note = f"mode=full findings={len(vulnerabilities)}"
        scan_log = (
            f"CWE scan complete ({_cwe_ids}): {len(vulnerabilities)} finding(s) "
            f"[AI suggestions: {ai_suggestion_count}] [{mode_note}] in {repo_path}"
        )

        logger.info(
            "SecurityScanStep: %d finding(s) detected, %d AI suggestions "
            "(cwe=%s, %s, elapsed=%.2fs)",
            len(vulnerabilities),
            ai_suggestion_count,
            _cwe_ids,
            mode_note,
            _elapsed,
        )

        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SUCCESS,
            log=scan_log,
            started_at=started_at,
            finished_at=finished_at,
            metadata={
                "vulnerabilities": vulnerabilities,
                "scan_log": scan_log,
                "cwe_scan_times": cwe_scan_times,
                "scan_mode": _scan_mode,
                "findings_before_filter": _findings_before_filter,
            },
        )
