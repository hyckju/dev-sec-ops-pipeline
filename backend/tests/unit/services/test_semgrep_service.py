"""SemgrepService 및 모듈 헬퍼 단위 테스트.

핵심 검증 항목:
- CWE_SCAN_CONFIG 구조 (6개 CWE 모두 rules/filter_keywords/label 보유)
- _normalize_cve_severity (NVD baseSeverity 대소문자/동의어 매핑)
- _match_cve (severity 매칭, round-robin, 빈 입력 처리)
- _has_semgrep_auth_or_config_error (인증/룰/타임아웃 오류 감지)
- SemgrepService.run_cwe_scan (runner/parser mock 기반)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.services.security.semgrep_service import (
    CWE_SCAN_CONFIG,
    SemgrepService,
    _has_semgrep_auth_or_config_error,
    _match_cve,
    _normalize_cve_severity,
)


# ── CWE_SCAN_CONFIG 구조 ─────────────────────────────────────────────

_EXPECTED_CWES = {"CWE-89", "CWE-79", "CWE-22", "CWE-918", "CWE-78", "CWE-798"}


def test_cwe_scan_config_covers_six_targeted_cwes():
    """신청서/docs에 명시된 6개 CWE가 모두 설정에 있어야 한다."""
    assert set(CWE_SCAN_CONFIG.keys()) == _EXPECTED_CWES


@pytest.mark.parametrize("cwe_id", sorted(_EXPECTED_CWES))
def test_cwe_scan_config_entry_has_required_keys(cwe_id):
    """각 CWE 항목은 rules/filter_keywords/label 세 키를 모두 가져야 한다."""
    entry = CWE_SCAN_CONFIG[cwe_id]
    assert entry["rules"], f"{cwe_id} has empty rules"
    assert isinstance(entry["filter_keywords"], list)
    assert entry["filter_keywords"], f"{cwe_id} has no filter_keywords"
    assert entry["label"], f"{cwe_id} has no label"


# ── _normalize_cve_severity ────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CRITICAL", "critical"),
        ("Critical", "critical"),
        ("HIGH", "high"),
        ("Medium", "medium"),
        ("MODERATE", "medium"),  # NVD가 가끔 moderate를 쓰는 케이스
        ("low", "low"),
        ("NONE", "low"),         # 0점도 low로 흡수
        ("unknown", "unknown"),  # 미지정은 원본 lower
    ],
)
def test_normalize_cve_severity(raw, expected):
    assert _normalize_cve_severity(raw) == expected


# ── _match_cve ─────────────────────────────────────────────────────────


def test_match_cve_returns_none_for_empty_pool():
    """CVE 목록이 비어있으면 None 반환."""
    finding = {"severity": "high"}
    assert _match_cve(finding, [], idx=0) is None


def test_match_cve_prefers_same_severity():
    """finding과 같은 severity의 CVE 풀에서 우선 선택해야 한다."""
    finding = {"severity": "high"}
    cves = [
        {"cve_id": "CVE-LOW-1",  "severity": "low"},
        {"cve_id": "CVE-HIGH-1", "severity": "HIGH"},
        {"cve_id": "CVE-HIGH-2", "severity": "high"},
    ]
    assert _match_cve(finding, cves, idx=0)["cve_id"] == "CVE-HIGH-1"
    assert _match_cve(finding, cves, idx=1)["cve_id"] == "CVE-HIGH-2"


def test_match_cve_round_robin_within_same_severity():
    """동일 severity 풀에서 idx가 풀 크기를 넘으면 순환해야 한다."""
    finding = {"severity": "high"}
    cves = [
        {"cve_id": "CVE-A", "severity": "high"},
        {"cve_id": "CVE-B", "severity": "high"},
    ]
    assert _match_cve(finding, cves, idx=0)["cve_id"] == "CVE-A"
    assert _match_cve(finding, cves, idx=1)["cve_id"] == "CVE-B"
    assert _match_cve(finding, cves, idx=2)["cve_id"] == "CVE-A"  # 순환


def test_match_cve_falls_back_to_full_pool_when_severity_missing():
    """같은 severity가 풀에 없으면 전체 풀에서 idx % len 선택."""
    finding = {"severity": "critical"}
    cves = [
        {"cve_id": "CVE-LOW-1", "severity": "low"},
        {"cve_id": "CVE-MED-1", "severity": "medium"},
    ]
    assert _match_cve(finding, cves, idx=0)["cve_id"] == "CVE-LOW-1"
    assert _match_cve(finding, cves, idx=1)["cve_id"] == "CVE-MED-1"
    assert _match_cve(finding, cves, idx=2)["cve_id"] == "CVE-LOW-1"


# ── _has_semgrep_auth_or_config_error ──────────────────────────────────


@pytest.mark.parametrize(
    "errors",
    [
        [{"type": "execution_error", "message": "boom"}],
        [{"type": "timeout_error", "message": "slow"}],
        [{"type": "scan_error", "message": "..."}],
        [{"type": "parse_error", "message": "..."}],
        [{"type": "other", "message": "Requires login to use this rule"}],
        [{"type": "other", "message": "Invalid API key"}],
        [{"type": "other", "message": "Failed to download config"}],
        [{"type": "other", "message": "executable not found"}],
        [{"type": "other", "message": "rule 'foo' not found"}],
    ],
)
def test_has_semgrep_auth_or_config_error_detects_known_failures(errors):
    assert _has_semgrep_auth_or_config_error(errors) is True


def test_has_semgrep_auth_or_config_error_ignores_benign_warnings():
    """파일 단위 파싱 경고처럼 무해한 항목은 False여야 한다."""
    errors = [{"type": "Syntax error", "message": "unexpected token in foo.html"}]
    assert _has_semgrep_auth_or_config_error(errors) is False


def test_has_semgrep_auth_or_config_error_handles_empty():
    assert _has_semgrep_auth_or_config_error([]) is False


# ── SemgrepService.run_cwe_scan (integration of runner+parser, mocked) ─


def _make_semgrep_service_with_mocks(parsed_findings, runner_errors=None):
    """runner/parser를 mock한 SemgrepService 인스턴스를 만든다."""
    svc = SemgrepService()
    svc._runner = MagicMock()
    svc._runner.run.return_value = {
        "results": [],  # parser mock이 이걸 무시함
        "errors": runner_errors or [],
        "stats": {},
        "paths": {"scanned": ["/repo/src/db.py"]},  # 빈 scan 방지
    }
    svc._parser = MagicMock()
    svc._parser.parse.return_value = parsed_findings
    # filter_by_cwe_ids는 입력을 그대로 통과시키도록 설정
    svc._parser.filter_by_cwe_ids.side_effect = lambda findings, *_a, **_kw: findings
    return svc


def test_run_cwe_scan_enriches_findings_with_cve_metadata(sample_semgrep_finding):
    """CWE-89 finding이 CWE-89 CVE 풀의 항목으로 enrichment되어야 한다."""
    svc = _make_semgrep_service_with_mocks([sample_semgrep_finding])
    cve_map = {
        "CWE-89": [
            {
                "cve_id": "CVE-2024-0001",
                "severity": "high",
                "description": "Sample CVE",
                "cvss_score": 7.5,
                "cvss_version": "3.1",
            }
        ]
    }
    result = svc.run_cwe_scan("/fake/repo", ["CWE-89"], cve_map)

    assert len(result) == 1
    enriched = result[0]
    assert enriched["cve_id"] == "CVE-2024-0001"
    assert enriched["cvss_score"] == 7.5
    assert enriched["cvss_version"] == "3.1"
    assert enriched["detected_cwe"] == "CWE-89"
    assert enriched["cve_description"] == "Sample CVE"


def test_run_cwe_scan_raises_on_runner_config_error():
    """runner errors에 인증/룰 오류가 있으면 RuntimeError로 승격되어야 한다."""
    svc = _make_semgrep_service_with_mocks(
        parsed_findings=[],
        runner_errors=[{"type": "execution_error", "message": "auth required"}],
    )
    with pytest.raises(RuntimeError, match="Semgrep auth/config/runtime error"):
        svc.run_cwe_scan("/fake/repo", ["CWE-89"], {"CWE-89": []})


def test_run_cwe_scan_unknown_cwe_falls_back_to_sql_injection_rules():
    """알 수 없는 CWE만 선택하면 SQL_INJECTION_RULES로 폴백."""
    from app.integrations.semgrep.runner import SQL_INJECTION_RULES

    svc = _make_semgrep_service_with_mocks([])
    svc.run_cwe_scan("/fake/repo", ["CWE-XXX"], {})

    # runner.run 호출 시 rules 키워드 인자 또는 두번째 positional이 SQL_INJECTION_RULES
    call = svc._runner.run.call_args
    rules = call.kwargs.get("rules") if call.kwargs.get("rules") is not None else call.args[1]
    assert rules == SQL_INJECTION_RULES
