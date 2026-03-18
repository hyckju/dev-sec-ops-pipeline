import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.db.models.pipeline import Pipeline
from app.db.models.project import Project
from app.schemas.pipeline import PipelineResponse
from app.schemas.project import ProjectResponse

router = APIRouter()

DbDep = Annotated[AsyncSession, Depends(get_db)]


@router.get("/", response_model=list[ProjectResponse])
async def list_projects(db: DbDep):
    """프로젝트 목록 조회 (최신순)"""
    result = await db.execute(
        select(Project).order_by(Project.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, db: DbDep):
    """프로젝트 상세 조회"""
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    return project


@router.get("/{project_id}/pipelines", response_model=list[PipelineResponse])
async def get_project_pipelines(project_id: uuid.UUID, db: DbDep):
    """특정 프로젝트의 파이프라인 목록 (최신순)"""
    project_result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )

    result = await db.execute(
        select(Pipeline)
        .where(Pipeline.project_id == project_id)
        .order_by(Pipeline.created_at.desc())
    )
    return result.scalars().all()
