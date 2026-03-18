import logging
from typing import Any

logger = logging.getLogger(__name__)

# semgrep severity 문자열 → 정규화된 레벨 매핑
_SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "inventory": "low",
    "experiment": "low",
}


def _normalize_severity(raw: str) -> str:
    """semgrep severity 값을 high / medium / low 중 하나로 변환한다."""
    return _SEVERITY_MAP.get(raw.lower(), "low")


def _extract_cwe(metadata: dict[str, Any]) -> str | None:
    """
    finding metadata 에서 CWE 정보를 추출한다.

    semgrep 룰에 따라 아래 형태 중 하나로 존재할 수 있다.
      - "cwe": "CWE-79"
      - "cwe": ["CWE-79", "CWE-80"]
    """
    cwe = metadata.get("cwe")
    if cwe is None:
        return None
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return str(cwe)


def _finding_key(finding: dict[str, Any]) -> tuple:
    """같은 취약점을 식별하기 위한 안정 키를 반환한다."""
    return (
        str(finding.get("rule_id", "")),
        str(finding.get("file_path", "")),
        int(finding.get("line_start", 0) or 0),
        int(finding.get("line_end", 0) or 0),
        str(finding.get("message", "")),
    )


class SemgrepParser:
    """semgrep --json 출력을 정규화된 finding 리스트로 변환하는 파서."""

    def parse(self, raw_output: dict) -> list[dict]:
        """
        semgrep JSON 출력(dict)을 받아 정규화된 finding 리스트를 반환한다.

        Args:
            raw_output: semgrep --json 출력 딕셔너리

        Returns:
            정규화된 finding 리스트. 각 항목 형식:
            {
                "rule_id":      str,
                "file_path":    str,
                "line_start":   int,
                "line_end":     int,
                "message":      str,
                "severity":     "high" | "medium" | "low",
                "code_snippet": str | None,
                "cwe":          str | None,
            }
        """
        results: list[dict] = raw_output.get("results", [])
        findings: list[dict] = []

        for item in results:
            try:
                check_id: str = item.get("check_id", "")
                extra: dict = item.get("extra", {})
                metadata: dict = extra.get("metadata", {})
                start: dict = item.get("start", {})
                end: dict = item.get("end", {})

                finding = {
                    "rule_id": check_id,
                    "file_path": item.get("path", ""),
                    "line_start": start.get("line", 0),
                    "line_end": end.get("line", 0),
                    "message": extra.get("message", ""),
                    "severity": _normalize_severity(extra.get("severity", "")),
                    "code_snippet": extra.get("lines"),
                    "cwe": _extract_cwe(metadata),
                }

                findings.append(finding)
            except Exception as exc:
                logger.warning(
                    "Failed to parse semgrep finding: %s | item=%s", exc, item
                )
                continue

        deduped = self._deduplicate_and_sort(findings)

        logger.debug(
            "SemgrepParser.parse: %d raw result(s) → %d finding(s) → %d deduped",
            len(results),
            len(findings),
            len(deduped),
        )
        return deduped

    def _deduplicate_and_sort(self, findings: list[dict]) -> list[dict]:
        """중복 finding을 제거하고 안정적인 정렬 순서를 보장한다."""
        unique: dict[tuple, dict] = {}
        for finding in findings:
            key = _finding_key(finding)
            if key not in unique:
                unique[key] = finding

        return sorted(unique.values(), key=_finding_key)

    def filter_by_cwe_ids(
        self,
        findings: list[dict],
        selected_cwe_ids: list[str],
        cwe_rule_keywords: dict[str, list[str]] | None = None,
    ) -> list[dict]:
        """
        선택된 CWE ID와 일치하는 finding만 반환한다.

        우선순위:
        1. finding의 'cwe' 메타데이터가 selected_cwe_ids 중 하나와 일치하면 포함
        2. cwe_rule_keywords 지정 시, rule_id에 해당 키워드가 포함되면 포함

        Args:
            findings:          parse()가 반환한 finding 목록
            selected_cwe_ids:  필터링할 CWE ID 목록 (예: ["CWE-89", "CWE-79"])
            cwe_rule_keywords: CWE별 rule_id 매칭 키워드 (폴백용)
                               예: {"CWE-89": ["sql"], "CWE-79": ["xss"]}

        Returns:
            필터링된 finding 목록
        """
        selected_upper = {c.upper() for c in selected_cwe_ids}
        kw_map = cwe_rule_keywords or {}

        # 선택된 모든 CWE의 rule_id 키워드를 통합
        all_keywords: list[str] = []
        for cwe in selected_cwe_ids:
            all_keywords.extend(kw_map.get(cwe, []))

        filtered: list[dict] = []
        for finding in findings:
            # "CWE-89: Improper Neutralization..." → "CWE-89" 로 정규화
            raw_cwe = (finding.get("cwe") or "").upper()
            cwe_val = raw_cwe.split(":")[0].strip()
            # 1) CWE 메타데이터 직접 매치
            if cwe_val and cwe_val in selected_upper:
                filtered.append(finding)
                continue
            # 2) rule_id 키워드 폴백
            rule_id = finding.get("rule_id", "").lower()
            if any(kw in rule_id for kw in all_keywords):
                filtered.append(finding)

        logger.debug(
            "filter_by_cwe_ids: %d → %d finding(s) (cwe_ids=%s)",
            len(findings),
            len(filtered),
            selected_cwe_ids,
        )
        return filtered

    def filter_sql_injection(self, results: list[dict]) -> list[dict]:
        """
        finding 리스트에서 rule_id에 'sql'(대소문자 무관)이 포함된 항목만 반환한다.

        Args:
            results: parse() 메서드가 반환한 finding 리스트

        Returns:
            SQL 인젝션 관련 finding 리스트
        """
        filtered = [
            r for r in results if "sql" in r.get("rule_id", "").lower()
        ]
        logger.debug(
            "filter_sql_injection: %d → %d finding(s)",
            len(results),
            len(filtered),
        )
        return filtered


def parse_semgrep_output(raw: dict) -> list[dict]:
    """
    하위 호환성을 위해 유지되는 모듈 레벨 함수.
    SemgrepParser().parse() 를 위임 호출한다.
    """
    return SemgrepParser().parse(raw)
