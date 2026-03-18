import logging
import os
from typing import Any

import httpx

from app.core.exceptions import NVDAPIException

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30.0


def _build_headers() -> dict[str, str]:
    """NVD API 키가 환경변수에 있을 때만 헤더에 포함한다."""
    headers: dict[str, str] = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _parse_cve_item(cve_item: dict[str, Any]) -> dict:
    """
    NVD CVE 2.0 응답의 개별 항목을 정규화된 dict로 변환한다.

    반환 형식:
        {
            "cve_id":       str,
            "cwe_id":       str | None,   # e.g. "CWE-89"
            "description":  str,
            "severity":     str,
            "cvss_score":   float | None,
            "cvss_version": str | None,   # "4.0" / "3.1" / "3.0" / "2.0"
            "published":    str,
            "kev_listed":   bool,         # CISA KEV 등재 여부 (기본 False, 이후 enrichment로 업데이트)
            "cpe_list":     list[str],    # 영향받는 제품 CPE 식별자 목록
        }
    """
    cve_data: dict = cve_item.get("cve", {})

    # cve_id
    cve_id: str = cve_data.get("id", "")

    # description (영문 우선)
    descriptions: list[dict] = cve_data.get("descriptions", [])
    description: str = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CWE – weaknesses[].description[].value (Primary 우선)
    cwe_id: str | None = None
    weaknesses: list[dict] = cve_data.get("weaknesses", [])
    # Primary 타입 우선, 없으면 첫 번째
    for wk in sorted(weaknesses, key=lambda w: w.get("type", "") != "Primary"):
        for wd in wk.get("description", []):
            val = wd.get("value", "")
            if val.upper().startswith("CWE-") and val.upper() != "CWE-NOINFO":
                cwe_id = val
                break
        if cwe_id:
            break

    # severity / cvss_score / cvss_version – CVSS v4.0 → v3.1 → v3.0 → v2.0 순으로 fallback
    severity: str = ""
    cvss_score: float | None = None
    cvss_version: str | None = None
    metrics: dict = cve_data.get("metrics", {})
    version_map = {
        "cvssMetricV40": "4.0",
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV2":  "2.0",
    }
    for metric_key, ver in version_map.items():
        metric_list: list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data: dict = metric_list[0].get("cvssData", {})
            severity = cvss_data.get("baseSeverity") or metric_list[0].get(
                "baseSeverity", ""
            )
            raw_score = cvss_data.get("baseScore") or metric_list[0].get("baseScore")
            if raw_score is not None:
                try:
                    cvss_score = float(raw_score)
                    cvss_version = ver
                except (TypeError, ValueError):
                    cvss_score = None
            if severity:
                break

    # published date
    published: str = cve_data.get("published", "")

    # CPE – configurations[].nodes[].cpeMatch[].criteria
    cpe_list: list[str] = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    cpe_list.append(cpe)
    # 중복 제거 (순서 유지)
    cpe_list = list(dict.fromkeys(cpe_list))

    return {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "description": description,
        "severity": severity.lower() if severity else "",
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "published": published,
        "kev_listed": False,
        "cpe_list": cpe_list,
    }


class NVDClient:
    """NVD REST API 2.0 클라이언트 (httpx.AsyncClient 기반)."""

    async def fetch_sql_injection_cves(
        self, results_per_page: int = 20
    ) -> list[dict]:
        """
        SQL Injection 키워드로 NVD CVE를 검색한다.

        Args:
            results_per_page: 가져올 CVE 수 (기본 20개)

        Returns:
            정규화된 CVE 딕셔너리 리스트:
            [{cve_id, description, severity, cvss_score, published}]

        Raises:
            NVDAPIException: HTTP 오류 발생 시
        """
        params: dict[str, Any] = {
            "keywordSearch": "SQL Injection",
            "resultsPerPage": results_per_page,
        }

        logger.info(
            "Fetching SQL Injection CVEs from NVD (resultsPerPage=%d)",
            results_per_page,
        )

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _NVD_BASE_URL, params=params, headers=_build_headers()
                )
                resp.raise_for_status()
                data: dict = resp.json()

            vulnerabilities: list[dict] = data.get("vulnerabilities", [])
            result = [_parse_cve_item(v) for v in vulnerabilities]
            logger.info("Fetched %d SQL Injection CVE(s) from NVD", len(result))
            return result

        except httpx.HTTPStatusError as exc:
            logger.error("NVD API HTTP error: %s", exc)
            raise NVDAPIException(
                message=f"NVD API HTTP error: {exc}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            logger.error("NVD API request error: %s", exc)
            raise NVDAPIException(message=f"NVD API request error: {exc}") from exc

    async def fetch_cve_detail(self, cve_id: str) -> dict:
        """
        단일 CVE ID로 상세 정보를 조회한다.

        Args:
            cve_id: 조회할 CVE ID (예: "CVE-2023-1234")

        Returns:
            정규화된 CVE 딕셔너리 {cve_id, description, severity, cvss_score, published}

        Raises:
            NVDAPIException: HTTP 오류 또는 CVE를 찾을 수 없는 경우
        """
        params: dict[str, str] = {"cveId": cve_id}
        logger.info("Fetching CVE detail for: %s", cve_id)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _NVD_BASE_URL, params=params, headers=_build_headers()
                )
                resp.raise_for_status()
                data: dict = resp.json()

            vulnerabilities: list[dict] = data.get("vulnerabilities", [])
            if not vulnerabilities:
                raise NVDAPIException(
                    message=f"CVE not found: {cve_id}",
                    status_code=404,
                )
            return _parse_cve_item(vulnerabilities[0])

        except NVDAPIException:
            raise
        except httpx.HTTPStatusError as exc:
            logger.error("NVD API HTTP error while fetching CVE '%s': %s", cve_id, exc)
            raise NVDAPIException(
                message=f"NVD API HTTP error: {exc}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "NVD API request error while fetching CVE '%s': %s", cve_id, exc
            )
            raise NVDAPIException(
                message=f"NVD API request error: {exc}"
            ) from exc

    async def search_cve_by_cwe_id(
        self, cwe_id: str, results_per_page: int = 20
    ) -> list[dict]:
        """
        NVD `cweId` 파라미터로 특정 CWE에 속하는 CVE를 조회한다.
        keywordSearch보다 정확하게 해당 CWE로 태그된 CVE만 반환한다.

        실패 시 빈 리스트를 반환한다.
        """
        params: dict[str, Any] = {
            "cweId": cwe_id,
            "resultsPerPage": results_per_page,
        }
        logger.info(
            "NVDClient.search_cve_by_cwe_id: cweId=%s resultsPerPage=%d",
            cwe_id, results_per_page,
        )
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _NVD_BASE_URL, params=params, headers=_build_headers()
                )
                resp.raise_for_status()
                data: dict = resp.json()

            vulnerabilities: list[dict] = data.get("vulnerabilities", [])
            result = [_parse_cve_item(v) for v in vulnerabilities]
            logger.info(
                "NVDClient.search_cve_by_cwe_id: %d CVE(s) for %s", len(result), cwe_id
            )
            return result

        except httpx.HTTPStatusError as exc:
            logger.warning(
                "NVD API HTTP error for cweId=%s: %s", cwe_id, exc
            )
            return []
        except httpx.RequestError as exc:
            logger.warning(
                "NVD API request error for cweId=%s: %s", cwe_id, exc
            )
            return []
        except Exception as exc:
            logger.error(
                "Unexpected error in search_cve_by_cwe_id (cweId=%s): %s", cwe_id, exc
            )
            return []

    async def search_cve(
        self, keyword: str, results_per_page: int = 10
    ) -> list[dict]:
        """
        keywordSearch 파라미터로 NVD CVE 검색을 수행한다.

        실패 시 예외를 올리지 않고 빈 리스트를 반환한다.
        """
        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _NVD_BASE_URL, params=params, headers=_build_headers()
                )
                resp.raise_for_status()
                data: dict = resp.json()

            vulnerabilities: list[dict] = data.get("vulnerabilities", [])
            return [_parse_cve_item(v) for v in vulnerabilities]

        except httpx.HTTPStatusError as exc:
            logger.warning(
                "NVD API HTTP error while searching '%s': %s", keyword, exc
            )
            return []
        except httpx.RequestError as exc:
            logger.warning(
                "NVD API request error while searching '%s': %s", keyword, exc
            )
            return []
        except Exception as exc:
            logger.error(
                "Unexpected error in NVDClient.search_cve (keyword=%s): %s",
                keyword,
                exc,
            )
            return []

    async def get_cve(self, cve_id: str) -> dict | None:
        """
        단일 CVE ID로 상세 정보를 조회한다.

        없거나 실패하면 None을 반환한다.
        """
        try:
            return await self.fetch_cve_detail(cve_id)
        except NVDAPIException:
            return None
