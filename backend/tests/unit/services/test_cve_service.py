"""CVEService 및 모듈 헬퍼 단위 테스트.

핵심 검증 항목:
- _language_to_keyword (지원/미지원 언어 매핑)
- _extract_cwe_id (CWE 접두어 정규화)
- _parse_cve_item (NVD 응답 → 정규화된 dict, integrations.nvd.client)
- CVEService.fetch_cves_by_cwe (캐시 hit/miss, cweId → keyword 폴백)
- CVEService.fetch_kev_cve_ids (HTTP 성공/실패 캐싱)
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.integrations.nvd.client import _parse_cve_item
from app.services.security import cve_service as cs
from app.services.security.cve_service import (
    CVEService,
    _extract_cwe_id,
    _language_to_keyword,
)


# ── _language_to_keyword ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "language,expected",
    [
        ("python", "python"),
        ("Python", "python"),         # 대소문자 무시
        ("  go  ", "golang"),         # 공백 strip
        ("nodejs", "node.js npm"),
        ("node", "node.js npm"),
        ("csharp", "c# .net"),
        ("rust", "rust"),
        ("unknown_lang", "unknown_lang"),  # 미지정은 lower로 그대로
    ],
)
def test_language_to_keyword(language, expected):
    assert _language_to_keyword(language) == expected


# ── _extract_cwe_id ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "finding,expected",
    [
        ({"cwe": "CWE-89"}, "CWE-89"),
        ({"cwe": "89"}, "CWE-89"),         # 접두어 자동 부여
        ({"cwe": "cwe-79"}, "cwe-79"),     # 대소문자 보존 (startswith는 upper 비교)
        ({"cwe": None}, None),
        ({}, None),
    ],
)
def test_extract_cwe_id(finding, expected):
    assert _extract_cwe_id(finding) == expected


# ── _parse_cve_item ────────────────────────────────────────────────────


def test_parse_cve_item_extracts_core_fields(sample_nvd_cve_item):
    """정상 NVD 응답이 정규화된 dict로 변환되는지 확인."""
    parsed = _parse_cve_item(sample_nvd_cve_item)
    assert parsed["cve_id"] == "CVE-2024-12345"
    assert parsed["cwe_id"] == "CWE-89"
    assert parsed["description"].startswith("Sample SQL injection")
    assert parsed["severity"] == "critical"  # baseSeverity가 lower화됨
    assert parsed["cvss_score"] == 9.8
    assert parsed["cvss_version"] == "3.1"
    assert parsed["kev_listed"] is False
    assert parsed["cpe_list"] == ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]


def test_parse_cve_item_prefers_english_description():
    """다국어 description 중 영문이 우선되어야 한다."""
    item = {
        "cve": {
            "id": "CVE-2024-0001",
            "descriptions": [
                {"lang": "ko", "value": "한국어 설명"},
                {"lang": "en", "value": "English description"},
            ],
        }
    }
    parsed = _parse_cve_item(item)
    assert parsed["description"] == "English description"


def test_parse_cve_item_falls_back_to_v30_when_no_v31():
    """CVSS v3.1이 없으면 v3.0으로 폴백해야 한다."""
    item = {
        "cve": {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {
                "cvssMetricV30": [
                    {"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}
                ]
            },
        }
    }
    parsed = _parse_cve_item(item)
    assert parsed["cvss_version"] == "3.0"
    assert parsed["cvss_score"] == 5.0
    assert parsed["severity"] == "medium"


def test_parse_cve_item_ignores_cwe_noinfo():
    """CWE-NOINFO 같은 비정보성 weakness는 cwe_id로 채택하지 않는다."""
    item = {
        "cve": {
            "id": "CVE-2024-0003",
            "descriptions": [{"lang": "en", "value": "x"}],
            "weaknesses": [
                {"type": "Primary", "description": [{"lang": "en", "value": "CWE-NOINFO"}]}
            ],
        }
    }
    parsed = _parse_cve_item(item)
    assert parsed["cwe_id"] is None


# ── CVEService.fetch_cves_by_cwe — 캐시 동작 ──────────────────────────


async def test_fetch_cves_by_cwe_caches_results(sample_parsed_cve):
    """첫 호출은 NVD 호출, 두 번째는 캐시 hit이어야 한다."""
    svc = CVEService()
    svc._client = MagicMock()
    svc._client.search_cve_by_cwe_id = AsyncMock(return_value=[sample_parsed_cve])
    svc._client.search_cve = AsyncMock(return_value=[])

    first = await svc.fetch_cves_by_cwe(["CWE-89"])
    second = await svc.fetch_cves_by_cwe(["CWE-89"])

    assert first == second
    assert first["CWE-89"][0]["cve_id"] == "CVE-2024-12345"
    # cweId 호출은 1번만 발생해야 한다 (캐시 hit)
    svc._client.search_cve_by_cwe_id.assert_awaited_once_with(
        "CWE-89", results_per_page=20
    )


async def test_fetch_cves_by_cwe_falls_back_to_keyword_when_cweid_returns_empty(
    sample_parsed_cve,
):
    """cweId 결과가 0건이면 keywordSearch로 폴백해야 한다."""
    svc = CVEService()
    svc._client = MagicMock()
    svc._client.search_cve_by_cwe_id = AsyncMock(return_value=[])
    svc._client.search_cve = AsyncMock(return_value=[sample_parsed_cve])

    result = await svc.fetch_cves_by_cwe(["CWE-89"])

    assert result["CWE-89"][0]["cve_id"] == "CVE-2024-12345"
    svc._client.search_cve.assert_awaited_once()


async def test_fetch_cves_by_cwe_expired_cache_refetches(sample_parsed_cve):
    """캐시가 만료되면 다시 NVD를 호출해야 한다."""
    svc = CVEService()
    svc._client = MagicMock()
    svc._client.search_cve_by_cwe_id = AsyncMock(return_value=[sample_parsed_cve])
    svc._client.search_cve = AsyncMock(return_value=[])

    await svc.fetch_cves_by_cwe(["CWE-89"])
    # 캐시 만료 강제
    cs._CWE_CVE_CACHE["CWE-89"]["expires_at"] = time.monotonic() - 1
    await svc.fetch_cves_by_cwe(["CWE-89"])

    assert svc._client.search_cve_by_cwe_id.await_count == 2


async def test_fetch_cves_by_cwe_handles_multiple_cwes_independently(sample_parsed_cve):
    """여러 CWE를 한 번에 요청하면 각각 NVD가 호출되고 키별로 매핑되어야 한다."""
    svc = CVEService()
    svc._client = MagicMock()

    cve_a = {**sample_parsed_cve, "cve_id": "CVE-AAA"}
    cve_b = {**sample_parsed_cve, "cve_id": "CVE-BBB"}

    async def _fake_search(cwe_id, results_per_page=20):
        return {"CWE-89": [cve_a], "CWE-79": [cve_b]}.get(cwe_id, [])

    svc._client.search_cve_by_cwe_id = AsyncMock(side_effect=_fake_search)
    svc._client.search_cve = AsyncMock(return_value=[])

    result = await svc.fetch_cves_by_cwe(["CWE-89", "CWE-79"])
    assert result["CWE-89"][0]["cve_id"] == "CVE-AAA"
    assert result["CWE-79"][0]["cve_id"] == "CVE-BBB"


# ── CVEService.fetch_kev_cve_ids ───────────────────────────────────────


async def test_fetch_kev_cve_ids_parses_feed_and_caches():
    """CISA KEV 응답을 파싱해 ID 셋으로 반환하고 2회차 호출은 캐시 hit이어야 한다."""
    svc = CVEService()
    fake_payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001"},
            {"cveID": "CVE-2024-0002"},
        ]
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=fake_payload)

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        first = await svc.fetch_kev_cve_ids()
        second = await svc.fetch_kev_cve_ids()

    assert first == {"CVE-2024-0001", "CVE-2024-0002"}
    assert second == first
    mock_client.get.assert_awaited_once()


async def test_fetch_kev_cve_ids_returns_existing_cache_on_http_failure():
    """HTTP 실패 시 예외 없이 기존 캐시(없으면 빈 셋)를 반환해야 한다."""
    svc = CVEService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=httpx.RequestError("network down"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await svc.fetch_kev_cve_ids()

    assert result == set()
