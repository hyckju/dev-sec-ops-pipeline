"""리포트 생성 스텝."""

import logging
from collections import Counter
from datetime import datetime, timezone

from app.core.constants import Severity, StepStatus
from app.services.pipeline.step_executor import StepResult

logger = logging.getLogger(__name__)

_STEP_TYPE = "report"

def _cwe_to_mitre_link(cwe: str | None) -> str | None:
    """CWE ID 문자열에서 MITRE CWE 상세 링크를 생성한다."""
    if not cwe:
        return None
    num_part = cwe.upper().replace("CWE-", "").split(":")[0].strip()
    if num_part.isdigit():
        return f"https://cwe.mitre.org/data/definitions/{num_part}.html"
    return None


# Severity 표시 순서 (심각도 높은 순)
_SEVERITY_ORDER: list[str] = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
]


def _build_summary(vulnerabilities: list[dict]) -> dict:
    """
    취약점 목록을 severity별로 집계하여 summary dict를 반환한다.

    Returns:
        {
            "total":    int,
            "critical": int,
            "high":     int,
            "medium":   int,
            "low":      int,
            "info":     int,
        }
    """
    counter: Counter[str] = Counter()
    for vuln in vulnerabilities:
        sev = vuln.get("severity", Severity.INFO.value)
        counter[sev] += 1

    return {
        "total": len(vulnerabilities),
        "critical": counter.get(Severity.CRITICAL.value, 0),
        "high": counter.get(Severity.HIGH.value, 0),
        "medium": counter.get(Severity.MEDIUM.value, 0),
        "low": counter.get(Severity.LOW.value, 0),
        "info": counter.get(Severity.INFO.value, 0),
    }


def _build_report_text(
    pipeline_id: str,
    summary: dict,
    vulnerabilities: list[dict],
    step_results: list[dict],
    selected_cwe_ids: list[str] | None = None,
    selected_cve_fields: list[str] | None = None,
    cwe_scan_times: dict[str, float] | None = None,
) -> str:
    """
    텍스트 기반 보안 리포트를 생성한다.

    Args:
        pipeline_id:    파이프라인 ID.
        summary:        _build_summary() 반환 값.
        vulnerabilities: 정규화된 취약점 목록.
        step_results:   각 스텝의 실행 결과 목록 (dict 형식).

    Returns:
        멀티라인 텍스트 리포트.
    """
    now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    # 기본값: cve_id, cwe, cvss_score, description
    _fields = set(selected_cve_fields) if selected_cve_fields else {"cve_id", "cwe", "cvss_score", "description"}

    lines.append("=" * 60)
    lines.append("  DevSecOps Pipeline Security Report")
    lines.append("=" * 60)
    lines.append(f"Pipeline ID : {pipeline_id}")
    lines.append(f"Generated   : {now_str}")
    lines.append("")

    # ── 스텝 실행 요약 ──────────────────────────────────────
    lines.append("[Pipeline Steps]")
    if step_results:
        for sr in step_results:
            step_type = sr.get("type", "?")
            status = sr.get("status", "?")
            started = sr.get("started_at", "")
            finished = sr.get("finished_at", "")
            line = f"  {step_type:<18} [{status}]"
            if started and finished:
                line += f"  {started} → {finished}"
            # 에러 메시지 완전히 제거
            lines.append(line)
    else:
        lines.append("  (no step data)")
    lines.append("")

    # ── CWE 스캔 범위 요약 ───────────────────────────────────
    if selected_cwe_ids:
        from app.services.security.semgrep_service import CWE_SCAN_CONFIG
        # CWE별 finding 수 집계
        cwe_counter: Counter[str] = Counter()
        for vuln in vulnerabilities:
            detected = vuln.get("detected_cwe") or vuln.get("cwe") or ""
            if detected:
                cwe_counter[detected.upper()] += 1

        lines.append("[Scanned CWE Coverage]")
        lines.append(f"  {'CWE':<10}  {'Vulnerability':<40}  {'Status':<18}  {'NVD+Semgrep+AI':>14}")
        lines.append(f"  {'─' * 80}")
        for cwe_id in selected_cwe_ids:
            label = CWE_SCAN_CONFIG.get(cwe_id, {}).get("label", cwe_id)
            count = cwe_counter.get(cwe_id.upper(), 0)
            status_str = f"{count} finding(s)" if count > 0 else "Not detected"
            t = cwe_scan_times.get(cwe_id) if cwe_scan_times else None
            time_str = f"  [{round(t)}s]" if t is not None else ""
            lines.append(f"  {cwe_id:<10}  {label:<40}  {status_str:<18}{time_str}")
        if cwe_scan_times:
            total_rounded = sum(round(t) for t in cwe_scan_times.values())
            t_mins = total_rounded // 60
            t_secs = total_rounded % 60
            t_display = f"{t_mins}m {t_secs}s ({total_rounded}s)" if t_mins > 0 else f"{total_rounded}s"
            lines.append(f"  {'─' * 80}")
            lines.append(f"  Total            : {t_display}  (NVD API + semgrep + AI post-processing)")
        lines.append("")

    # ── 취약점 집계 ─────────────────────────────────────────
    lines.append("[Vulnerability Summary]")
    lines.append(f"  Total    : {summary['total']}")
    lines.append(f"  Critical : {summary['critical']}")
    lines.append(f"  High     : {summary['high']}")
    lines.append(f"  Medium   : {summary['medium']}")
    lines.append(f"  Low      : {summary['low']}")
    lines.append(f"  Info     : {summary['info']}")
    lines.append("")

    # ── 취약점 상세 ─────────────────────────────────────────
    if vulnerabilities:
        lines.append("[Vulnerability Details]")
        # severity 높은 순으로 정렬
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: _SEVERITY_ORDER.index(
                v.get("severity", Severity.INFO.value)
                if v.get("severity") in _SEVERITY_ORDER
                else Severity.INFO.value
            ),
        )
        for idx, vuln in enumerate(sorted_vulns, start=1):
            original_title = vuln.get("title", "N/A")
            lines.append(f"  [{idx}] [{vuln.get('severity', '?').upper()}] {original_title}")
            if vuln.get("file_path"):
                line_no = vuln.get("line_number")
                location = vuln["file_path"]
                if line_no:
                    location += f":{line_no}"
                lines.append(f"      Location  : {location}")
            if vuln.get("rule_id"):
                lines.append(f"      Rule ID   : {vuln['rule_id']}")
            if vuln.get("cwe") and "cwe" in _fields:
                lines.append(f"      CWE       : {vuln['cwe']}")
                mitre_url = _cwe_to_mitre_link(vuln["cwe"])
                if mitre_url:
                    lines.append(f"      MITRE     : {mitre_url}")
            # CVSS 점수 (NVD 기반)
            cvss_score = vuln.get("cvss_score")
            cvss_ver = vuln.get("cvss_version") or "3.1"
            if cvss_score is not None and "cvss_score" in _fields:
                lines.append(f"      CVSS v{cvss_ver}  : {cvss_score:.1f} / 10.0")
            cve_ids = vuln.get("related_cve_ids", [])
            if cve_ids and "cve_id" in _fields:
                lines.append(f"      CVEs      : {', '.join(cve_ids[:5])}")
                for cve_id in cve_ids[:3]:
                    lines.append(f"      NVD Link  : https://nvd.nist.gov/vuln/detail/{cve_id}")
            if vuln.get("kev_listed") and "kev_listed" in _fields:
                lines.append("      KEV       : ⚠️  CISA Known Exploited Vulnerability")
            if vuln.get("cpe_list") and "cpe_list" in _fields:
                cpe_items = (vuln["cpe_list"] or [])[:3]
                if cpe_items:
                    lines.append(f"      CPE       : {', '.join(cpe_items)}")
            if vuln.get("description") and "description" in _fields:
                desc = vuln["description"]
                if len(desc) > 200:
                    desc = desc[:197] + "..."
                lines.append(f"      Detail    : {desc}")
            suggestion = vuln.get("suggestion", "")
            if suggestion:
                lines.append(f"      Recommendation  : {suggestion}")
            else:
                lines.append("      Recommendation  : -")
            lines.append("")
    else:
        lines.append("[Vulnerability Details]")
        lines.append("  No vulnerabilities found.")
        lines.append("")

    lines.append("=" * 60)
    lines.append("  End of Report")
    lines.append("=" * 60)

    return "\n".join(lines)


class ReportStep:
    """파이프라인 결과를 집계하여 보안 리포트를 생성하는 스텝."""

    async def run(
        self,
        pipeline_id: str,
        vulnerabilities: list[dict],
        step_results: list[dict],
        selected_cwe_ids: list[str] | None = None,
        selected_cve_fields: list[str] | None = None,
        github_url: str = "",
        cwe_scan_times: dict[str, float] | None = None,
    ) -> StepResult:
        """
        취약점 severity별 집계 및 텍스트 리포트를 생성한다.

        Args:
            pipeline_id:     현재 파이프라인 ID.
            vulnerabilities: SecurityScanStep이 반환한 정규화된 취약점 목록.
            step_results:    지금까지 실행된 스텝 결과 목록 (dict 직렬화 형식).

        Returns:
            StepResult.
            metadata 키:
                - summary     (dict): severity별 집계.
                - report_text (str):  텍스트 리포트.
        """
        started_at = datetime.now(tz=timezone.utc)

        logger.info(
            "ReportStep: generating report for pipeline_id=%s "
            "(vuln_count=%d, step_count=%d)",
            pipeline_id,
            len(vulnerabilities),
            len(step_results),
        )

        summary = _build_summary(vulnerabilities)

        report_text = _build_report_text(
            pipeline_id, summary, vulnerabilities, step_results,
            selected_cwe_ids, selected_cve_fields, cwe_scan_times,
        )

        finished_at = datetime.now(tz=timezone.utc)
        logger.info(
            "ReportStep: complete — total=%d critical=%d high=%d medium=%d",
            summary["total"],
            summary["critical"],
            summary["high"],
            summary["medium"],
        )

        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SUCCESS,
            log=f"Report generated: {summary['total']} vulnerability finding(s)",
            started_at=started_at,
            finished_at=finished_at,
            metadata={
                "summary": summary,
                "report_text": report_text,
            },
        )
