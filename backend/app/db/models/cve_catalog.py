from sqlalchemy import Boolean, Float, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import BaseModel


class CveCatalog(BaseModel):
    """NVD에서 수집한 CVE 항목을 저장하는 카탈로그 테이블."""

    __tablename__ = "cve_catalog"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_cve_catalog_cve_id"),)

    cve_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        comment="CVE 식별자 (e.g. CVE-2021-44228)",
    )
    cwe_id: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
        comment="CWE 분류 코드 (e.g. CWE-89)",
    )
    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="CVSS 기본 점수 (0.0 ~ 10.0)",
    )
    cvss_version: Mapped[str | None] = mapped_column(
        String(8),
        nullable=True,
        comment="CVSS 버전 (3.1 / 3.0 / 2.0)",
    )
    severity: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        index=True,
        comment="CVSS 기반 심각도 (critical/high/medium/low)",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="취약점 설명 (영문)",
    )
    published: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="NVD 공개 날짜 (ISO 8601)",
    )
    kev_listed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="CISA KEV(Known Exploited Vulnerabilities) 등재 여부",
    )
    cpe_list: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
        comment="영향받는 제품 CPE 식별자 목록 (e.g. cpe:2.3:a:apache:log4j:...)",
    )

    def __repr__(self) -> str:
        return (
            f"<CveCatalog cve_id={self.cve_id!r} "
            f"cwe_id={self.cwe_id!r} cvss={self.cvss_score}>"
        )
