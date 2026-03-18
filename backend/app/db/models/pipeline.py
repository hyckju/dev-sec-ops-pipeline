import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import PipelineStatus
from app.db.base import BaseModel

if TYPE_CHECKING:
    from app.db.models.project import Project
    from app.db.models.vulnerability import Vulnerability


class Pipeline(BaseModel):
    __tablename__ = "pipelines"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[PipelineStatus] = mapped_column(
        Enum(PipelineStatus, name="pipelinestatus"),
        nullable=False,
        default=PipelineStatus.PENDING,
        index=True,
    )
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # 각 스텝의 실행 결과를 JSON 배열로 단순 저장
    # 예: [{"type": "clone", "status": "success", "started_at": ..., "log": "..."}]
    steps: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON,
        nullable=True,
        default=list,
        comment="파이프라인 각 스텝의 실행 결과 목록",
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="pipelines")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="pipeline",
        cascade="all, delete-orphan",
        order_by="Vulnerability.severity",
    )

    def __repr__(self) -> str:
        return f"<Pipeline id={self.id} status={self.status} project_id={self.project_id}>"
