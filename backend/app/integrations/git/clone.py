import asyncio
import logging

from app.core.exceptions import RepositoryCloneException

logger = logging.getLogger(__name__)

_CLONE_TIMEOUT = 60  # seconds


async def clone_repo(github_url: str, target_dir: str) -> str:
    """
    GitHub 저장소를 target_dir 로 클론한다.

    Parameters
    ----------
    github_url : str
        클론할 GitHub 저장소 URL (예: https://github.com/owner/repo.git)
    target_dir : str
        클론 결과를 저장할 로컬 디렉터리 경로

    Returns
    -------
    str
        클론이 완료된 디렉터리 경로 (target_dir 그대로 반환)

    Raises
    ------
    RepositoryCloneException
        git clone 명령이 실패하거나 타임아웃이 발생한 경우
    """
    logger.info("Cloning repository: %s → %s", github_url, target_dir)

    try:
        proc = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth", "1",
            github_url,
            target_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=_CLONE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RepositoryCloneException(
                f"git clone timed out after {_CLONE_TIMEOUT}s for URL: {github_url}",
                github_url=github_url,
            )

        if proc.returncode != 0:
            error_msg = stderr.decode(errors="replace").strip()
            logger.error(
                "git clone failed (exit %d) for %s: %s",
                proc.returncode,
                github_url,
                error_msg,
            )
            raise RepositoryCloneException(
                f"git clone failed (exit {proc.returncode}): {error_msg}",
                github_url=github_url,
            )

    except RepositoryCloneException:
        raise
    except FileNotFoundError:
        raise RepositoryCloneException(
            "git binary not found. Is git installed?",
            github_url=github_url,
        )
    except Exception as exc:
        raise RepositoryCloneException(
            f"Unexpected error during git clone: {exc}",
            github_url=github_url,
        ) from exc

    logger.info("Repository cloned successfully to: %s", target_dir)
    return target_dir
