"""테스트 공통 픽스처 및 헬퍼.

NVD/Semgrep 같은 외부 의존을 가짜로 대체하는 빌딩 블록을 모아둔다.
모듈 단위 캐시(_CWE_CVE_CACHE, _kev_cache)는 테스트 간 격리를 위해 자동 리셋된다.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_cve_module_caches():
    """모듈 전역 캐시가 테스트 간 상태를 흘리지 않도록 매 테스트마다 비운다."""
    from app.services.security import cve_service as cs

    cs._CWE_CVE_CACHE.clear()
    cs._kev_cache["ids"] = set()
    cs._kev_cache["expires_at"] = 0.0
    yield
    cs._CWE_CVE_CACHE.clear()
    cs._kev_cache["ids"] = set()
    cs._kev_cache["expires_at"] = 0.0


@pytest.fixture
def sample_nvd_cve_item() -> dict:
    """NVD CVE 2.0 응답 1건 raw 형식 — _parse_cve_item 입력용."""
    return {
        "cve": {
            "id": "CVE-2024-12345",
            "descriptions": [
                {"lang": "en", "value": "Sample SQL injection vulnerability."},
                {"lang": "ko", "value": "샘플 SQL 인젝션 취약점."},
            ],
            "weaknesses": [
                {
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-89"}],
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                    }
                ]
            },
            "published": "2024-01-15T00:00:00.000",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
        }
    }


@pytest.fixture
def sample_parsed_cve() -> dict:
    """CVEService.fetch_cves_by_cwe()가 반환하는 정규화된 CVE dict 1건."""
    return {
        "cve_id": "CVE-2024-12345",
        "cwe_id": "CWE-89",
        "description": "Sample SQL injection vulnerability.",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_version": "3.1",
        "published": "2024-01-15T00:00:00.000",
        "kev_listed": False,
        "cpe_list": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
    }


@pytest.fixture
def sample_semgrep_finding() -> dict:
    """SemgrepParser.parse()가 반환하는 정규화된 finding 1건."""
    return {
        "rule_id": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
        "file_path": "src/db.py",
        "line_start": 42,
        "line_end": 42,
        "message": "Detected raw SQL execution.",
        "severity": "high",
        "code_snippet": "cursor.execute(query)",
        "cwe": "CWE-89: Improper Neutralization of Special Elements",
    }
