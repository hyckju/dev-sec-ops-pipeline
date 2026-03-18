import uuid
from typing import Any

from sqlalchemy import ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import BaseModel


class Report(BaseModel):
    __tablename__ = "reports"

    __table_args__ = (
        UniqueConstraint("pipeline_id", name="uq_reports_pipeline_id"),
    )

    pipeline_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pipelines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment=(
            "파이프라인 결과 요약. "
            "예: {total_vulnerabilities, critical, high, medium, low, info, test_passed}"
        ),
    )
    html_content: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="렌더링된 HTML 보안 리포트 전문",
    )

    # Relationship (단방향: Pipeline 모델에는 역참조 미설정)
    pipeline = relationship("Pipeline", foreign_keys=[pipeline_id])

    def __repr__(self) -> str:
        return f"<Report id={self.id} pipeline_id={self.pipeline_id}>"
