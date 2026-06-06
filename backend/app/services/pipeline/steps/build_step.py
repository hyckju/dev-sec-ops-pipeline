"""빌드 실행 스텝."""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

from app.core.constants import StepStatus
from app.services.pipeline.step_executor import StepResult

logger = logging.getLogger(__name__)

_STEP_TYPE = "build"
_TIMEOUT = 900


def _run(cmd: list[str], cwd: str) -> tuple[int, str]:
    """커맨드를 subprocess로 실행하고 (returncode, combined_output)을 반환한다."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT,
        )
        combined = (result.stdout + result.stderr).strip()
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        return -1, f"Command timed out after {_TIMEOUT}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, f"Executable not found: {cmd[0]}"


class BuildStep:
    """언어/빌드 도구에 맞게 프로젝트 빌드를 수행하는 파이프라인 스텝."""

    async def run(
        self,
        repo_path: str,
        language: str,
        package_manager: str,
        install_status: str = "pending",
        test_status: str = "pending",
    ) -> StepResult:
        started_at = datetime.now(tz=timezone.utc)

        if not repo_path or not os.path.isdir(repo_path):
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                error=f"repo_path does not exist: {repo_path!r}",
            )

        # install_status가 SUCCESS가 아니어도 빌드 시도

        cmd, skip_reason = self._resolve_command(repo_path, language, package_manager)
        if skip_reason:
            logger.info("BuildStep SKIPPED: %s", skip_reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=skip_reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )

        logger.info("BuildStep: running %s in %s", cmd, repo_path)
        returncode, output = _run(cmd, cwd=repo_path)
        finished_at = datetime.now(tz=timezone.utc)

        if returncode != 0:
            logger.error("BuildStep failed (exit %d): %s", returncode, output[:500])
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                log=output,
                started_at=started_at,
                finished_at=finished_at,
                error=f"Build command exited with code {returncode}",
            )

        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SUCCESS,
            log=output,
            started_at=started_at,
            finished_at=finished_at,
            metadata={"build_command": " ".join(cmd)},
        )

    def _resolve_command(
        self,
        repo_path: str,
        language: str,
        package_manager: str,
    ) -> tuple[list[str], str]:
        if language == "node":
            pkg_json_path = os.path.join(repo_path, "package.json")
            if not os.path.isfile(pkg_json_path):
                return [], "package.json not found; skipping node build"
            try:
                with open(pkg_json_path, encoding="utf-8") as fh:
                    pkg_data = json.load(fh)
            except (OSError, json.JSONDecodeError):
                pkg_data = {}

            scripts = pkg_data.get("scripts", {})
            if "build" not in scripts:
                return [], "No 'build' script in package.json; skipping node build"

            if package_manager == "yarn":
                return ["yarn", "build"], ""
            if package_manager == "pnpm":
                return ["pnpm", "build"], ""
            return ["npm", "run", "build"], ""

        if language == "java":
            if os.path.isfile(os.path.join(repo_path, "mvnw")):
                return ["./mvnw", "-q", "-DskipTests", "package"], ""
            if os.path.isfile(os.path.join(repo_path, "pom.xml")):
                return ["mvn", "-q", "-DskipTests", "package"], ""
            if os.path.isfile(os.path.join(repo_path, "gradlew")):
                return ["./gradlew", "build", "-x", "test"], ""
            if os.path.isfile(os.path.join(repo_path, "build.gradle")) or os.path.isfile(os.path.join(repo_path, "build.gradle.kts")):
                return ["gradle", "build", "-x", "test"], ""
            return [], "No maven/gradle build file found; skipping java build"

        if language == "go":
            if os.path.isfile(os.path.join(repo_path, "go.mod")):
                return ["go", "build", "./..."], ""
            return [], "go.mod not found; skipping go build"

        if language == "rust":
            if os.path.isfile(os.path.join(repo_path, "Cargo.toml")):
                return ["cargo", "build", "--release"], ""
            return [], "Cargo.toml not found; skipping rust build"

        if language == "python":
            if os.path.isfile(os.path.join(repo_path, "pyproject.toml")) or os.path.isfile(os.path.join(repo_path, "setup.py")):
                return ["python", "-m", "build"], ""
            return [], "No pyproject.toml/setup.py found; skipping python build"

        return [], f"Build for language '{language}' is not configured; skipping"
