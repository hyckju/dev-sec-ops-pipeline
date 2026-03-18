import asyncio
import logging
import time

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.nvd.client import NVDClient

logger = logging.getLogger(__name__)

# CISA KEV 피드 URL
_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
# KEV 캐시: {"ids": set(), "expires_at": float}
_kev_cache: dict = {"ids": set(), "expires_at": 0.0}
_KEV_CACHE_TTL = 86400  # 24시간

# CWE ID → NVD keywordSearch 매핑
_CWE_NVD_KEYWORD: dict[str, str] = {
    "CWE-89":  "SQL Injection",
    "CWE-79":  "Cross-Site Scripting XSS",
    "CWE-22":  "Path Traversal",
    "CWE-918": "Server Side Request Forgery SSRF",
    "CWE-78":  "OS Command Injection",
    "CWE-798": "hardcoded credentials API key",
}

# CWE별 캐시: {"CWE-89": {"data": [...], "expires_at": float}, ...}
_CWE_CVE_CACHE: dict[str, dict] = {}

# 캐시 TTL (초)
_CACHE_TTL = 3600  # 1시간

# 언어 → NVD 키워드 매핑
_LANGUAGE_KEYWORD_MAP: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "nodejs": "node.js npm",
    "node": "node.js npm",
    "java": "java",
    "go": "golang",
    "ruby": "ruby",
    "php": "php",
    "rust": "rust",
    "c": "c language",
    "cpp": "c++",
    "csharp": "c# .net",
    "dotnet": ".net",
    "kotlin": "kotlin android",
    "swift": "swift apple",
    "scala": "scala",
    "r": "r language cran",
    "dart": "dart flutter",
    "elixir": "elixir erlang",
    "haskell": "haskell",
}


def _language_to_keyword(language: str) -> str:
    """언어명을 NVD 검색에 적합한 키워드로 변환한다."""
    normalized = language.lower().strip()
    return _LANGUAGE_KEYWORD_MAP.get(normalized, normalized)


def _extract_cwe_id(finding: dict) -> str | None:
    """finding 딕셔너리에서 CWE ID 문자열을 추출한다."""
    cwe: str | None = finding.get("cwe")
    if not cwe:
        return None
    cwe_str = str(cwe).strip()
    if not cwe_str.upper().startswith("CWE-"):
        cwe_str = f"CWE-{cwe_str}"
    return cwe_str


class CVEService:
    """NVD API를 통한 CVE 조회 및 finding 매핑 서비스."""

    def __init__(self) -> None:
        self._client = NVDClient()

    async def fetch_cves_by_cwe(
        self,
        selected_cwe_ids: list[str],
        limit_per_cwe: int = 20,
    ) -> dict[str, list[dict]]:
        """
        선택된 CWE ID 목록에 대해 각각 NVD에서 CVE를 조회하고
        {cwe_id: [cve_dict, ...]} 형태로 반환한다. 결과는 CWE별로 캐싱된다.

        Args:
            selected_cwe_ids: 조회할 CWE ID 목록 (예: ["CWE-89", "CWE-79"])
            limit_per_cwe:    CWE당 최대 CVE 수 (기본 20)

        Returns:
            {cwe_id: list[cve_dict]} — 알 수 없는 CWE는 빈 리스트
        """
        now = time.monotonic()
        result: dict[str, list[dict]] = {}

        for cwe_id in selected_cwe_ids:
            cache_entry = _CWE_CVE_CACHE.get(cwe_id, {})
            if cache_entry and now < cache_entry.get("expires_at", 0.0):
                logger.debug("CVEService.fetch_cves_by_cwe: cache hit for %s", cwe_id)
                result[cwe_id] = cache_entry["data"]
                continue

            keyword = _CWE_NVD_KEYWORD.get(cwe_id, cwe_id)
            logger.info(
                "CVEService.fetch_cves_by_cwe: fetching NVD for %s (keyword=%r)", cwe_id, keyword
            )
            # cweId 파라미터 직접 조회 — 해당 CWE로 정확히 태그된 CVE만 반환
            cves = await self._client.search_cve_by_cwe_id(cwe_id, results_per_page=limit_per_cwe)
            # 결과 없으면 키워드 검색으로 폴백
            if not cves:
                logger.info(
                    "CVEService.fetch_cves_by_cwe: cweId=%s returned 0, fallback keyword=%r",
                    cwe_id, keyword,
                )
                cves = await self._client.search_cve(keyword, results_per_page=limit_per_cwe)
            _CWE_CVE_CACHE[cwe_id] = {"data": cves, "expires_at": now + _CACHE_TTL}
            result[cwe_id] = cves
            logger.info("CVEService.fetch_cves_by_cwe: %d CVE(s) for %s", len(cves), cwe_id)

        return result

    async def get_sql_injection_cves(self) -> list[dict]:
        """SQL 인젝션 관련 CVE 목록을 반환한다 (하위 호환성 유지)."""
        cve_map = await self.fetch_cves_by_cwe(["CWE-89"])
        return cve_map.get("CWE-89", [])

    async def fetch_recent_cves(
        self, language: str, limit: int = 20
    ) -> list[dict]:
        """
        지정한 프로그래밍 언어와 관련된 최근 CVE 목록을 반환한다.

        Returns:
            [{cve_id, description, severity, cvss_score, published}]
        """
        keyword = _language_to_keyword(language)
        logger.info(
            "Fetching recent CVEs for language='%s' (keyword='%s', limit=%d)",
            language,
            keyword,
            limit,
        )
        cves = await self._client.search_cve(keyword, results_per_page=limit)
        logger.info(
            "Fetched %d CVE(s) for language='%s'", len(cves), language
        )
        return cves

    async def get_cve_detail(self, cve_id: str) -> dict | None:
        """
        단일 CVE ID의 상세 정보를 반환한다.
        조회 실패 시 None을 반환한다.
        """
        return await self._client.get_cve(cve_id)

    async def save_cves_to_db(self, cves: list[dict], db: AsyncSession) -> int:
        """
        CVE 목록을 cve_catalog 테이블에 upsert(INSERT ON CONFLICT DO UPDATE)한다.

        Args:
            cves: _parse_cve_item() 형식의 CVE 딕셔너리 리스트
            db:   AsyncSession

        Returns:
            저장된 레코드 수
        """
        from app.db.models.cve_catalog import CveCatalog

        if not cves:
            return 0

        rows = [
            {
                "cve_id":       cve["cve_id"],
                "cwe_id":       cve.get("cwe_id"),
                "cvss_score":   cve.get("cvss_score"),
                "cvss_version": cve.get("cvss_version"),
                "severity":     cve.get("severity", "").lower() or None,
                "description":  cve.get("description"),
                "published":    cve.get("published"),
                "kev_listed":   cve.get("kev_listed", False),
                "cpe_list":     cve.get("cpe_list") or [],
            }
            for cve in cves
            if cve.get("cve_id")
        ]

        if not rows:
            return 0

        stmt = pg_insert(CveCatalog).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "cwe_id":       stmt.excluded.cwe_id,
                "cvss_score":   stmt.excluded.cvss_score,
                "cvss_version": stmt.excluded.cvss_version,
                "severity":     stmt.excluded.severity,
                "description":  stmt.excluded.description,
                "published":    stmt.excluded.published,
                "cpe_list":     stmt.excluded.cpe_list,
            },
        )
        await db.execute(stmt)

        # KEV 등재 여부 업데이트 (CISA 피드 기준)
        cve_ids = [r["cve_id"] for r in rows]
        await self.update_kev_flags(db, cve_ids)

        logger.info("CVEService.save_cves_to_db: upserted %d CVE(s)", len(rows))
        return len(rows)

    async def fetch_kev_cve_ids(self) -> set[str]:
        """
        CISA Known Exploited Vulnerabilities(KEV) 피드에서 CVE ID 집합을 반환한다.
        결과는 24시간 캐싱된다. 실패 시 기존 캐시(혹은 빈 셋)를 반환한다.
        """
        now = time.monotonic()
        if _kev_cache["ids"] and now < _kev_cache["expires_at"]:
            return _kev_cache["ids"]
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(_KEV_FEED_URL)
                resp.raise_for_status()
                data = resp.json()
            kev_ids: set[str] = {v["cveID"] for v in data.get("vulnerabilities", [])}
            _kev_cache["ids"] = kev_ids
            _kev_cache["expires_at"] = now + _KEV_CACHE_TTL
            logger.info("CVEService.fetch_kev_cve_ids: loaded %d KEV CVE IDs", len(kev_ids))
            return kev_ids
        except Exception as exc:
            logger.warning("CVEService.fetch_kev_cve_ids: CISA KEV fetch failed — %s", exc)
            return _kev_cache["ids"]

    async def update_kev_flags(self, db: AsyncSession, cve_ids: list[str]) -> None:
        """
        cve_ids 중 CISA KEV에 등재된 항목의 kev_listed 컬럼을 True로 업데이트한다.
        KEV 피드 취득 실패 시 조용히 넘어간다.
        """
        from app.db.models.cve_catalog import CveCatalog
        from sqlalchemy import update as sa_update

        if not cve_ids:
            return
        kev_ids = await self.fetch_kev_cve_ids()
        matching = [cid for cid in cve_ids if cid in kev_ids]
        if not matching:
            logger.debug("CVEService.update_kev_flags: no KEV matches in %d CVE(s)", len(cve_ids))
            return
        stmt = (
            sa_update(CveCatalog)
            .where(CveCatalog.cve_id.in_(matching))
            .values(kev_listed=True)
        )
        await db.execute(stmt)
        logger.info(
            "CVEService.update_kev_flags: marked %d CVE(s) as KEV-listed", len(matching)
        )

    async def match_findings_to_cves(
        self, findings: list[dict]
    ) -> list[dict]:
        """
        semgrep finding 리스트를 받아 각 finding에 CWE 정보가 있으면
        관련 CVE를 NVD에서 검색하고 "related_cves" 필드를 추가하여 반환한다.

        Returns:
            원본 finding + "related_cves" 필드가 추가된 리스트
        """
        enriched: list[dict] = []
        cwe_cache: dict[str, list[dict]] = {}

        async def _fetch_for_finding(finding: dict) -> dict:
            result = dict(finding)
            cwe_id = _extract_cwe_id(finding)

            if not cwe_id:
                result["related_cves"] = []
                return result

            if cwe_id not in cwe_cache:
                logger.debug("Searching CVEs for %s", cwe_id)
                cves = await self._client.search_cve(cwe_id, results_per_page=5)
                cwe_cache[cwe_id] = cves

            result["related_cves"] = cwe_cache[cwe_id]
            return result

        semaphore = asyncio.Semaphore(5)

        async def _limited_fetch(finding: dict) -> dict:
            async with semaphore:
                return await _fetch_for_finding(finding)

        tasks = [_limited_fetch(f) for f in findings]
        enriched = list(await asyncio.gather(*tasks))

        logger.info(
            "match_findings_to_cves complete: %d finding(s) enriched",
            len(enriched),
        )
        return enriched
