from pydantic import BaseModel, HttpUrl
import uuid
from datetime import datetime


class ProjectCreate(BaseModel):
    github_url: HttpUrl
    name: str
    description: str | None = None


class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    github_url: str
    description: str | None
    language: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
