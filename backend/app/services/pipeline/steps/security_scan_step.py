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

        Returns:
            StepResult.
            metadata 키:
                - vulnerabilities (list[dict]): 정규화된 취약점 목록.
                - scan_log (str): semgrep 실행 로그 요약.
        """
        started_at = datetime.now(tz=timezone.utc)

        _cwe_ids = selected_cwe_ids or ["CWE-89"]
        _fallback_cve_map: dict[str, list[dict]] = cve_map if cve_map is not None else {"CWE-89": cve_list}

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
        scan_log = (
            f"CWE scan complete ({_cwe_ids}): {len(vulnerabilities)} finding(s) "
            f"[AI suggestions: {ai_suggestion_count}] in {repo_path}"
        )

        logger.info(
            "SecurityScanStep: %d finding(s) detected, %d AI suggestions (cwe=%s)",
            len(vulnerabilities),
            ai_suggestion_count,
            _cwe_ids,
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
            },
        )
