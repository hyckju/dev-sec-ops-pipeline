"""GitHub 저장소 클론 스텝."""

import logging
import subprocess
from datetime import datetime, timezone

from app.core.constants import StepStatus
from app.core.exceptions import RepositoryCloneException
from app.services.pipeline.step_executor import StepResult

logger = logging.getLogger(__name__)

_STEP_TYPE = "clone"


class CloneStep:
    """GitHub 저장소를 로컬 워크스페이스로 클론하는 파이프라인 스텝."""

    async def run(
        self,
        github_url: str,
        workspace_dir: str,
        pipeline_id: str,
    ) -> StepResult:
        """
        git clone을 실행하여 저장소를 로컬에 내려받는다.

        Args:
            github_url:    클론할 GitHub 저장소 URL (https 또는 ssh).
            workspace_dir: 클론 결과를 저장할 기본 디렉터리 경로.
            pipeline_id:   현재 파이프라인 ID (로그 추적용).

        Returns:
            StepResult.
            성공 시 metadata에 아래 키가 포함된다:
                - repo_path  (str): 클론된 저장소 디렉터리 절대 경로.
                - commit_sha (str): HEAD 커밋 SHA (40자).
                - branch     (str): 현재 브랜치 이름.

        Raises:
            RepositoryCloneException: git clone 실패 시 (StepResult로 래핑됨).
        """
        started_at = datetime.now(tz=timezone.utc)

        if not github_url:
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                error="github_url is required",
            )
        if not workspace_dir:
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                error="workspace_dir is required",
            )

        # 저장소 이름을 URL에서 추출하여 대상 디렉터리 결정
        import os
        repo_name = github_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # pipeline_id를 디렉터리 이름에 포함하여 충돌 방지
        target_dir = os.path.join(workspace_dir, f"{repo_name}_{pipeline_id[:8]}")

        logger.info(
            "[pipeline=%s] CloneStep: cloning %s → %s",
            pipeline_id,
            github_url,
            target_dir,
        )

        try:
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", github_url, target_dir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
        except subprocess.TimeoutExpired as exc:
            finished_at = datetime.now(tz=timezone.utc)
            msg = f"git clone timed out after 300s for URL: {github_url}"
            logger.error("[pipeline=%s] %s", pipeline_id, msg)
            raise RepositoryCloneException(message=msg, github_url=github_url) from exc
        except FileNotFoundError as exc:
            finished_at = datetime.now(tz=timezone.utc)
            msg = "git executable not found on PATH"
            logger.error("[pipeline=%s] %s", pipeline_id, msg)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                error=msg,
            )

        log_output = (clone_result.stdout + clone_result.stderr).strip()

        if clone_result.returncode != 0:
            finished_at = datetime.now(tz=timezone.utc)
            msg = (
                f"git clone failed (exit {clone_result.returncode}): "
                f"{clone_result.stderr.strip()}"
            )
            logger.error("[pipeline=%s] %s", pipeline_id, msg)
            raise RepositoryCloneException(message=msg, github_url=github_url)

        # HEAD 커밋 SHA 수집
        commit_sha = ""
        sha_result = subprocess.run(
            ["git", "-C", target_dir, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if sha_result.returncode == 0:
            commit_sha = sha_result.stdout.strip()

        # 현재 브랜치 이름 수집
        branch = ""
        branch_result = subprocess.run(
            ["git", "-C", target_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if branch_result.returncode == 0:
            branch = branch_result.stdout.strip()

        finished_at = datetime.now(tz=timezone.utc)
        logger.info(
            "[pipeline=%s] CloneStep succeeded: repo_path=%s commit=%s branch=%s",
            pipeline_id,
            target_dir,
            commit_sha[:7] if commit_sha else "?",
            branch,
        )

        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SUCCESS,
            log=log_output,
            started_at=started_at,
            finished_at=finished_at,
            metadata={
                "repo_path": target_dir,
                "commit_sha": commit_sha,
                "branch": branch,
            },
        )
