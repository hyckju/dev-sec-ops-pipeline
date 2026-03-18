"""파이프라인 생성 및 조회 서비스."""

import logging
import uuid
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.pipeline import Pipeline
from app.db.models.project import Project

logger = logging.getLogger(__name__)


def _extract_repo_name(github_url: str) -> str:
    """
    GitHub URL에서 저장소 이름을 추출한다.

    예: "https://github.com/owner/repo.git" → "repo"
         "https://github.com/owner/repo"     → "repo"
    """
    path = urlparse(github_url).path.rstrip("/")
    name = path.split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or github_url


class PipelineService:
    """
    파이프라인 생성·실행·조회를 담당하는 애플리케이션 서비스.

    모든 메서드는 async이며 호출자가 AsyncSession을 제공해야 한다.
    """

    async def create_and_run(
        self,
        github_url: str,
        db: AsyncSession,
        selected_cwe_ids: list[str] | None = None,
        selected_cve_fields: list[str] | None = None,
    ) -> Pipeline:
        """
        프로젝트가 없으면 github_url 기준으로 생성하고,
        신규 Pipeline 레코드를 만든 뒤 PipelineRunner를 백그라운드로 실행한다.

        Note:
            PipelineRunner.run()은 별도 asyncio.Task로 구동되므로
            이 메서드는 Pipeline DB 레코드 생성 직후 반환된다.
            실제 분석은 백그라운드에서 계속된다.

        Args:
            github_url: 분석할 GitHub 저장소 URL.
            db:         비동기 SQLAlchemy 세션.

        Returns:
            생성된 Pipeline 인스턴스 (status=PENDING).
        """
        # ── Project 조회 또는 생성 ──────────────────────────────────
        project = await self._get_or_create_project(github_url, db)

        # ── Pipeline 생성 ───────────────────────────────────────────
        pipeline = Pipeline(project_id=project.id)
        db.add(pipeline)
        await db.flush()  # id 확보
        await db.refresh(pipeline)

        pipeline_id = str(pipeline.id)
        logger.info(
            "PipelineService: created pipeline %s for project %s (url=%s)",
            pipeline_id,
            project.id,
            github_url,
        )

        # ── 백그라운드 실행 (독립 세션 사용) ──────────────────────────
        import asyncio
        from app.services.pipeline.pipeline_runner import PipelineRunner

        async def _run_in_new_session() -> None:
            from app.db.session import AsyncSessionLocal
            async with AsyncSessionLocal() as bg_db:
                async with bg_db.begin():
                    runner = PipelineRunner()
                    await runner.run(
                        pipeline_id=pipeline_id,
                        github_url=github_url,
                        db=bg_db,
                        selected_cwe_ids=selected_cwe_ids or ["CWE-89"],
                        selected_cve_fields=selected_cve_fields,
                    )

        asyncio.create_task(_run_in_new_session())

        return pipeline

    async def get_pipeline(
        self,
        pipeline_id: str,
        db: AsyncSession,
    ) -> Pipeline | None:
        """
        단일 Pipeline을 ID로 조회한다.

        Args:
            pipeline_id: UUID 문자열.
            db:          비동기 SQLAlchemy 세션.

        Returns:
            Pipeline 인스턴스 또는 None (미존재 시).
        """
        try:
            uid = uuid.UUID(pipeline_id)
        except ValueError:
            logger.warning("get_pipeline: invalid UUID format: %s", pipeline_id)
            return None

        stmt = (
            select(Pipeline)
            .where(Pipeline.id == uid)
            .options(selectinload(Pipeline.vulnerabilities))
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_pipelines(
        self,
        db: AsyncSession,
        project_id: str | None = None,
    ) -> list[Pipeline]:
        """
        Pipeline 목록을 조회한다.

        Args:
            db:         비동기 SQLAlchemy 세션.
            project_id: (선택) 특정 프로젝트의 파이프라인만 조회할 때 지정.

        Returns:
            Pipeline 인스턴스 리스트 (created_at 내림차순).
        """
        stmt = select(Pipeline).order_by(Pipeline.created_at.desc())

        if project_id is not None:
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                logger.warning(
                    "list_pipelines: invalid project_id format: %s", project_id
                )
                return []
            stmt = stmt.where(Pipeline.project_id == project_uuid)

        result = await db.execute(stmt)
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    async def _get_or_create_project(
        self, github_url: str, db: AsyncSession
    ) -> Project:
        """
        github_url과 일치하는 Project를 반환하거나, 없으면 새로 생성한다.

        Args:
            github_url: GitHub 저장소 URL.
            db:         비동기 SQLAlchemy 세션.

        Returns:
            Project 인스턴스.
        """
        stmt = select(Project).where(Project.github_url == github_url)
        result = await db.execute(stmt)
        project = result.scalar_one_or_none()

        if project is not None:
            logger.debug(
                "PipelineService: found existing project %s for url=%s",
                project.id,
                github_url,
            )
            return project

        repo_name = _extract_repo_name(github_url)
        project = Project(
            name=repo_name,
            github_url=github_url,
        )
        db.add(project)
        await db.flush()
        await db.refresh(project)

        logger.info(
            "PipelineService: created new project %s (name=%r, url=%s)",
            project.id,
            project.name,
            github_url,
        )
        return project
