import uuid
from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import BaseModel

if TYPE_CHECKING:
    from app.db.models.pipeline import Pipeline


class Project(BaseModel):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    github_url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="자동 감지된 주 프로그래밍 언어",
    )

    # Relationships
    pipelines: Mapped[list["Pipeline"]] = relationship(
        "Pipeline",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="Pipeline.created_at.desc()",
    )

    def __repr__(self) -> str:
        return f"<Project id={self.id} name={self.name!r}>"
