"""의존성 설치 스텝."""

import logging
import os
import subprocess
from datetime import datetime, timezone

from app.core.constants import StepStatus
from app.services.pipeline.step_executor import StepResult

logger = logging.getLogger(__name__)

_STEP_TYPE = "install"

# subprocess 실행 타임아웃 (초)
_TIMEOUT = 60


def _run(cmd: list[str], cwd: str) -> tuple[int, str]:
    """커맨드를 subprocess로 실행하고 (returncode, combined_output)을 반환한다."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        combined = (result.stdout + result.stderr).strip()
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        return -1, f"Command timed out after {_TIMEOUT}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, f"Executable not found: {cmd[0]}"


class InstallStep:
    """언어/패키지 매니저에 맞게 의존성을 설치하는 파이프라인 스텝."""

    async def run(
        self,
        repo_path: str,
        language: str,
        package_manager: str,
    ) -> StepResult:
        """
        저장소의 의존성을 설치한다.

        지원:
        - python + pip:    ``pip install -r requirements.txt``
        - python + poetry: ``poetry install --no-interaction``
        - python + pipenv: ``pipenv install``
        - python + uv:     ``uv sync``
        - python + pdm:    ``pdm install``
        - node   + npm:    ``npm install``
        - node   + yarn:   ``yarn install``
        - node   + pnpm:   ``pnpm install``
        - java   + maven:  ``mvn -q -DskipTests dependency:go-offline``
        - java   + gradle: ``gradle dependencies``
        - scala  + sbt:    ``sbt update``
        - go:              ``go mod download``
        - rust:            ``cargo fetch``
        - php   + composer:``composer install --no-interaction``
        - ruby  + bundler: ``bundle install``
        - csharp+ dotnet:  ``dotnet restore``
        - swift:           ``swift package resolve``
        - dart:            ``dart pub get``
        - elixir:          ``mix deps.get``
        - haskell+stack:   ``stack build --only-dependencies``
        - haskell+cabal:   ``cabal update``
        - c/c++ + cmake:   ``cmake -S . -B build``
        - c/c++ + make:    ``make -n`` (의존성/타깃 점검)
        언어가 "unknown"이거나 지원하지 않는 조합이면 스텝을 SKIPPED로 처리한다.

        Args:
            repo_path:       클론된 저장소 절대 경로.
            language:        감지된 언어 ("python", "node", ...).
            package_manager: 감지된 패키지 매니저 ("pip", "poetry", "npm", ...).

        Returns:
            StepResult (metadata에 install_log 포함).
        """
        started_at = datetime.now(tz=timezone.utc)

        if not repo_path or not os.path.isdir(repo_path):
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                error=f"repo_path does not exist: {repo_path!r}",
            )

        cmd, skip_reason = self._resolve_command(
            repo_path, language, package_manager
        )

        if skip_reason:
            logger.info("InstallStep SKIPPED: %s", skip_reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=skip_reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )

        logger.info("InstallStep: running %s in %s", cmd, repo_path)
        returncode, output = _run(cmd, cwd=repo_path)

        # 실행 파일 미설치 등으로 실패하면 python 계열은 pip 기반 폴백을 1회 시도
        if returncode == -1 and output.startswith("Executable not found:"):
            fallback_cmd, fallback_reason = self._resolve_fallback_command(
                repo_path=repo_path,
                language=language,
                package_manager=package_manager,
            )
            if fallback_cmd:
                logger.warning(
                    "InstallStep: primary installer unavailable (%s). fallback: %s",
                    output,
                    fallback_reason,
                )
                fb_code, fb_output = _run(fallback_cmd, cwd=repo_path)
                if fb_code == 0:
                    finished_at = datetime.now(tz=timezone.utc)
                    return StepResult(
                        type=_STEP_TYPE,
                        status=StepStatus.SUCCESS,
                        log=(
                            f"Primary failed: {output}\n"
                            f"Fallback used: {' '.join(fallback_cmd)}\n"
                            f"{fb_output}"
                        ).strip(),
                        started_at=started_at,
                        finished_at=finished_at,
                    )
                returncode = fb_code
                output = (
                    f"Primary failed: {output}\n"
                    f"Fallback failed ({' '.join(fallback_cmd)}): {fb_output}"
                ).strip()

        finished_at = datetime.now(tz=timezone.utc)

        if returncode != 0:
            logger.warning(
                "InstallStep SKIPPED (exit %d): %s", returncode, output[:500]
            )
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=f"Install command skipped (exit {returncode}): {output}",
                started_at=started_at,
                finished_at=finished_at,
                error=f"Install command skipped with code {returncode}",
            )

        logger.info("InstallStep succeeded")
        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SUCCESS,
            log=output,
            started_at=started_at,
            finished_at=finished_at,
        )

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _resolve_command(
        self,
        repo_path: str,
        language: str,
        package_manager: str,
    ) -> tuple[list[str], str]:
        """
        언어와 패키지 매니저에 맞는 커맨드를 결정한다.

        Returns:
            (cmd, skip_reason).
            - 실행할 커맨드가 있으면 skip_reason == "".
            - 스킵해야 하면 cmd == [] and skip_reason != "".
        """
        if package_manager == "poetry":
            return ["poetry", "install", "--no-interaction"], ""

        if package_manager == "pipenv":
            return ["pipenv", "install"], ""

        if package_manager == "uv":
            return ["uv", "sync"], ""

        if package_manager == "pdm":
            return ["pdm", "install"], ""

        if package_manager == "pip":
            req_path = os.path.join(repo_path, "requirements.txt")
            if os.path.isfile(req_path):
                return ["pip", "install", "-r", "requirements.txt"], ""
            return [], "requirements.txt not found; skipping pip install"

        if package_manager == "yarn":
            return ["yarn", "install", "--frozen-lockfile"], ""

        if package_manager == "pnpm":
            return ["pnpm", "install", "--frozen-lockfile"], ""

        if package_manager == "npm":
            return ["npm", "install", "--prefer-offline"], ""

        if package_manager == "maven":
            if os.path.isfile(os.path.join(repo_path, "mvnw")):
                return ["./mvnw", "-q", "-DskipTests", "dependency:go-offline"], ""
            return ["mvn", "-q", "-DskipTests", "dependency:go-offline"], ""

        if package_manager == "gradle":
            if os.path.isfile(os.path.join(repo_path, "gradlew")):
                return ["./gradlew", "dependencies"], ""
            return ["gradle", "dependencies"], ""

        if package_manager == "sbt":
            return ["sbt", "update"], ""

        if package_manager == "go":
            if os.path.isfile(os.path.join(repo_path, "go.mod")):
                return ["go", "mod", "download"], ""
            return [], "go.mod not found; skipping go dependency download"

        if package_manager == "cargo":
            if os.path.isfile(os.path.join(repo_path, "Cargo.toml")):
                return ["cargo", "fetch"], ""
            return [], "Cargo.toml not found; skipping cargo fetch"

        if package_manager == "composer":
            if os.path.isfile(os.path.join(repo_path, "composer.json")):
                return ["composer", "install", "--no-interaction"], ""
            return [], "composer.json not found; skipping composer install"

        if package_manager == "bundler":
            if os.path.isfile(os.path.join(repo_path, "Gemfile")):
                return ["bundle", "install"], ""
            return [], "Gemfile not found; skipping bundler install"

        if package_manager == "dotnet":
            return ["dotnet", "restore"], ""

        if package_manager == "swift":
            if os.path.isfile(os.path.join(repo_path, "Package.swift")):
                return ["swift", "package", "resolve"], ""
            return [], "Package.swift not found; skipping swift package resolve"

        if package_manager == "pub":
            if os.path.isfile(os.path.join(repo_path, "pubspec.yaml")) or os.path.isfile(os.path.join(repo_path, "pubspec.yml")):
                return ["dart", "pub", "get"], ""
            return [], "pubspec.yaml not found; skipping dart pub get"

        if package_manager == "mix":
            if os.path.isfile(os.path.join(repo_path, "mix.exs")):
                return ["mix", "deps.get"], ""
            return [], "mix.exs not found; skipping mix deps.get"

        if package_manager == "stack":
            if os.path.isfile(os.path.join(repo_path, "stack.yaml")):
                return ["stack", "build", "--only-dependencies"], ""
            return [], "stack.yaml not found; skipping stack dependency install"

        if package_manager == "cabal":
            return ["cabal", "update"], ""

        if package_manager == "cmake":
            if os.path.isfile(os.path.join(repo_path, "CMakeLists.txt")):
                return ["cmake", "-S", ".", "-B", "build"], ""
            return [], "CMakeLists.txt not found; skipping cmake configure"

        if package_manager == "make":
            if os.path.isfile(os.path.join(repo_path, "Makefile")) or os.path.isfile(os.path.join(repo_path, "makefile")):
                return ["make", "-n"], ""
            return [], "Makefile not found; skipping make dry-run"

        return [], (
            f"No install command mapped (language={language}, "
            f"package_manager={package_manager}); skipping install step"
        )

    def _resolve_fallback_command(
        self,
        repo_path: str,
        language: str,
        package_manager: str,
    ) -> tuple[list[str], str]:
        if language != "python":
            return [], ""

        if package_manager not in {"poetry", "pipenv", "uv", "pdm"}:
            return [], ""

        req_path = os.path.join(repo_path, "requirements.txt")
        if os.path.isfile(req_path):
            return ["pip", "install", "-r", "requirements.txt"], "fallback to pip requirements"

        if os.path.isfile(os.path.join(repo_path, "pyproject.toml")):
            return ["python", "-m", "pip", "install", "."], "fallback to pip install ."

        return [], ""
