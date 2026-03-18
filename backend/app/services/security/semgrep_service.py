import logging

from app.integrations.semgrep.parser import SemgrepParser
from app.integrations.semgrep.runner import SQL_INJECTION_RULES, SemgrepRunner

# CWE ID → Semgrep 룰 팩, rule_id 필터 키워드, 표시 레이블
CWE_SCAN_CONFIG: dict[str, dict] = {
    "CWE-89":  {
        "rules":           ["p/sql-injection"],
        "filter_keywords": ["sql"],
        "label":           "SQL Injection",
    },
    "CWE-79":  {
        "rules":           ["p/xss"],
        "filter_keywords": ["xss", "cross-site-scripting", "cross-site"],
        "label":           "Cross-Site Scripting (XSS)",
    },
    "CWE-22":  {
        "rules":           ["p/java"],
        "filter_keywords": ["path-traversal", "traversal", "directory", "tainted-file", "httpservlet-path"],
        "label":           "Path Traversal",
    },
    "CWE-918": {
        "rules":           ["p/java"],
        "filter_keywords": ["ssrf", "request-forgery", "server-side-request", "tainted-url"],
        "label":           "Server-Side Request Forgery (SSRF)",
    },
    "CWE-78":  {
        "rules":           ["p/command-injection"],
        "filter_keywords": ["command", "shell", "os-injection", "exec"],
        "label":           "Command Injection",
    },
    "CWE-798": {
        "rules":           ["p/secrets"],
        "filter_keywords": ["secrets", "hardcode", "credential", "apikey", "token"],
        "label":           "Hardcoded API Key / Credentials",
    },
}

logger = logging.getLogger(__name__)

# CVE severity 문자열 → 정규화된 레벨 매핑 (NVD baseSeverity 대소문자 혼용 대응)
_CVE_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "none": "low",
}


def _has_semgrep_auth_or_config_error(errors: list[dict]) -> bool:
    """semgrep 결과의 errors에서 인증/룰 설정 오류 여부를 판단한다."""
    for err in errors:
        err_types = err.get("type", [])
        if isinstance(err_types, str):
            err_types = [err_types]
        err_types_lower = {str(t).lower() for t in err_types}
        if err_types_lower & {"execution_error", "timeout_error", "scan_error", "parse_error"}:
            return True

        blob = " ".join([
            str(err.get("type", "")),
            str(err.get("message", "")),
            str(err.get("code", "")),
            str(err),
        ]).lower()
        if (
            "requires login" in blob
            or "semgrep login" in blob
            or "invalid api key" in blob
            or "failed to download" in blob
            or "could not download" in blob
            or "executable not found" in blob
            or "binary not found" in blob
            or "timed out" in blob
            or ("rule" in blob and "not found" in blob)
        ):
            return True
    return False


def _normalize_cve_severity(raw: str) -> str:
    """NVD baseSeverity를 소문자 정규화된 값으로 변환한다."""
    return _CVE_SEVERITY_MAP.get(raw.lower(), raw.lower())


def _match_cve(finding: dict, cve_list: list[dict], idx: int = 0) -> dict | None:
    """
    finding의 severity와 맞는 CVE를 cve_list에서 선택한다.
    severity별 풀 내에서 idx를 기준으로 순환(round-robin)하여
    여러 finding이 같은 severity를 가져도 각기 다른 CVE를 받도록 한다.

    우선순위:
    1. finding severity와 동일한 severity를 가진 CVE 풀에서 idx % 풀크기 선택
    2. 해당 severity CVE가 없으면 전체 cve_list에서 idx % 전체크기 선택
    3. cve_list가 비어 있으면 None
    """
    if not cve_list:
        return None

    finding_severity = finding.get("severity", "").lower()

    matched: list[dict] = [
        cve for cve in cve_list
        if _normalize_cve_severity(cve.get("severity", "")) == finding_severity
    ]
    pool = matched if matched else cve_list
    return pool[idx % len(pool)]


class SemgrepService:
    """semgrep 실행 및 SQL 인젝션 취약점 결과 정규화를 담당하는 서비스."""

    def __init__(self) -> None:
        self._runner = SemgrepRunner()
        self._parser = SemgrepParser()

    def run_sql_injection_scan(
        self, repo_path: str, cve_list: list[dict]
    ) -> list[dict]:
        """
        SQL 인젝션 전용 semgrep 룰로 저장소를 스캔하고, 각 취약점에
        cve_list에서 매칭되는 CVE 정보를 attach하여 반환한다.

        Args:
            repo_path: 스캔 대상 로컬 저장소 경로
            cve_list: CVEService.get_sql_injection_cves()가 반환한 CVE 목록

        Returns:
            취약점 딕셔너리 리스트. 각 항목 형식:
            {
                "rule_id":         str,
                "file_path":       str,
                "line_start":      int,
                "message":         str,
                "severity":        str,
                "cve_id":          str | None,
                "cve_description": str | None,
                "cvss_score":      float | None,
                "code_snippet":    str | None,
            }
        """
        logger.info(
            "Starting SQL injection scan for: %s (CVE pool size: %d)",
            repo_path,
            len(cve_list),
        )

        # semgrep 실행
        raw_output = self._runner.run(repo_path, rules=SQL_INJECTION_RULES)

        # 전체 결과 파싱
        all_findings = self._parser.parse(raw_output)

        # SQL 인젝션 관련 finding만 필터링
        sql_findings = self._parser.filter_sql_injection(all_findings)

        logger.info(
            "semgrep scan complete: %d total finding(s), %d SQL injection finding(s)",
            len(all_findings),
            len(sql_findings),
        )

        # 각 finding에 매칭 CVE 정보 attach
        enriched: list[dict] = []
        for i, finding in enumerate(sql_findings):
            matched_cve = _match_cve(finding, cve_list, idx=i)

            enriched.append(
                {
                    "rule_id": finding.get("rule_id", ""),
                    "file_path": finding.get("file_path", ""),
                    "line_start": finding.get("line_start", 0),
                    "message": finding.get("message", ""),
                    "severity": finding.get("severity", ""),
                    "cwe": finding.get("cwe"),
                    "cve_id": matched_cve.get("cve_id") if matched_cve else None,
                    "cve_description": (
                        matched_cve.get("description") if matched_cve else None
                    ),
                    "cvss_score": (
                        matched_cve.get("cvss_score") if matched_cve else None
                    ),
                    "cvss_version": (
                        matched_cve.get("cvss_version") if matched_cve else None
                    ),
                    "code_snippet": finding.get("code_snippet"),
                }
            )

        logger.info(
            "run_sql_injection_scan done: %d enriched finding(s) for path: %s",
            len(enriched),
            repo_path,
        )
        return enriched

    def run_cwe_scan(
        self,
        repo_path: str,
        selected_cwe_ids: list[str],
        cve_map: dict[str, list[dict]],
    ) -> list[dict]:
        """
        선택된 CWE 목록에 맞는 Semgrep 룰을 실행하고 각 finding에
        CVE 정보를 attach하여 반환한다.

        Args:
            repo_path:         스캔 대상 저장소 경로
            selected_cwe_ids:  분석할 CWE ID 목록 (예: ["CWE-89", "CWE-79"])
            cve_map:           CVEService.fetch_cves_by_cwe() 반환값
                               {cwe_id: [cve_dict, ...]}

        Returns:
            취약점 딕셔너리 리스트 (각 finding에 detected_cwe 필드 포함)
        """
        # 선택된 CWE에 필요한 모든 Semgrep 룰 팩 수집 (중복 제거, 순서 유지)
        seen: set[str] = set()
        all_rules: list[str] = []
        for cwe_id in selected_cwe_ids:
            for rule in CWE_SCAN_CONFIG.get(cwe_id, {}).get("rules", []):
                if rule not in seen:
                    seen.add(rule)
                    all_rules.append(rule)

        scan_rules = all_rules or SQL_INJECTION_RULES

        logger.info(
            "run_cwe_scan: selected_cwe=%s rules=%s cve_count=%d",
            selected_cwe_ids,
            scan_rules,
            sum(len(v) for v in cve_map.values()),
        )

        # CWE별 rule_id 필터 키워드 수집
        cwe_rule_keywords: dict[str, list[str]] = {
            cwe_id: CWE_SCAN_CONFIG.get(cwe_id, {}).get("filter_keywords", [])
            for cwe_id in selected_cwe_ids
        }

        def _scan_and_parse(rules: list[str] | None) -> list[dict]:
            raw_output = self._runner.run(repo_path, rules=rules)
            raw_errors: list[dict] = raw_output.get("errors", [])
            if _has_semgrep_auth_or_config_error(raw_errors):
                raise RuntimeError(
                    "Semgrep auth/config/runtime error detected. Check semgrep login and runner environment."
                )
            return self._parser.parse(raw_output)

        # 선택된 CWE 룰팩으로 스캔
        all_findings = _scan_and_parse(scan_rules)

        logger.info(
            "run_cwe_scan: semgrep returned %d raw finding(s) for %s",
            len(all_findings), repo_path,
        )

        # 선택된 CWE 기준으로 필터링
        filtered = self._parser.filter_by_cwe_ids(
            all_findings, selected_cwe_ids, cwe_rule_keywords
        )

        logger.info(
            "run_cwe_scan: %d total → %d filtered finding(s)",
            len(all_findings),
            len(filtered),
        )

        # 각 finding에 CVE 정보 attach
        flat_cves = [cve for cves in cve_map.values() for cve in cves]
        enriched: list[dict] = []
        for i, finding in enumerate(filtered):
            # finding의 CWE에 맞는 CVE 풀 선택
            # CWE 값이 "CWE-89: Improper..." 형태일 수 있으므로 앞부분만 추출
            raw_cwe = finding.get("cwe") or ""
            finding_cwe = raw_cwe.split(":")[0].strip().upper() if raw_cwe else ""
            cve_pool = cve_map.get(finding_cwe, flat_cves) if finding_cwe else flat_cves
            matched_cve = _match_cve(finding, cve_pool, idx=i) if cve_pool else None

            enriched.append({
                "rule_id":         finding.get("rule_id", ""),
                "file_path":       finding.get("file_path", ""),
                "line_start":      finding.get("line_start", 0),
                "message":         finding.get("message", ""),
                "severity":        finding.get("severity", ""),
                "cwe":             finding.get("cwe"),
                "detected_cwe":    finding_cwe or None,
                "cve_id":          matched_cve.get("cve_id") if matched_cve else None,
                "cve_description": matched_cve.get("description") if matched_cve else None,
                "cvss_score":      matched_cve.get("cvss_score") if matched_cve else None,
                "cvss_version":    matched_cve.get("cvss_version") if matched_cve else None,
                "code_snippet":    finding.get("code_snippet"),
            })

        logger.info(
            "run_cwe_scan done: %d enriched finding(s) for %s",
            len(enriched),
            repo_path,
        )
        return enriched

    async def scan(self, repo_path: str, timeout: int = 300) -> list[dict]:
        """
        하위 호환성을 위해 유지되는 전체 스캔 메서드.
        timeout 파라미터는 settings.SEMGREP_TIMEOUT 을 사용하므로 무시된다.

        Returns:
            정규화된 finding 리스트 (cve 정보 없음)
        """
        raw = self._runner.run(repo_path)
        findings = self._parser.parse(raw)

        logger.info(
            "semgrep scan complete: %d finding(s) for path: %s",
            len(findings),
            repo_path,
        )
        return findings
