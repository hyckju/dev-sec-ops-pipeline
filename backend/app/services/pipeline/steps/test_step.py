"""테스트 실행 스텝."""

import logging
import os
import re
import subprocess
from datetime import datetime, timezone

from app.core.constants import StepStatus
from app.services.pipeline.step_executor import StepResult

logger = logging.getLogger(__name__)

_STEP_TYPE = "test"
_TIMEOUT = 600


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


def _parse_pytest_output(output: str) -> tuple[int, int, int]:
    """
    pytest 출력에서 passed / failed / total 수를 파싱한다.

    예: "3 passed, 1 failed, 1 error in 0.12s"
    Returns: (passed, failed, total)
    """
    passed = 0
    failed = 0

    passed_match = re.search(r"(\d+)\s+passed", output)
    if passed_match:
        passed = int(passed_match.group(1))

    failed_match = re.search(r"(\d+)\s+(?:failed|error)", output)
    if failed_match:
        failed = int(failed_match.group(1))

    return passed, failed, passed + failed


def _parse_npm_test_output(output: str) -> tuple[int, int, int]:
    """
    npm test / jest 출력에서 passed / failed / total 수를 파싱한다.

    예: "Tests:       5 passed, 1 failed, 6 total"
    Returns: (passed, failed, total)
    """
    passed = 0
    failed = 0
    total = 0

    # Jest 형식
    passed_match = re.search(r"(\d+)\s+passed", output)
    if passed_match:
        passed = int(passed_match.group(1))

    failed_match = re.search(r"(\d+)\s+failed", output)
    if failed_match:
        failed = int(failed_match.group(1))

    total_match = re.search(r"(\d+)\s+total", output)
    if total_match:
        total = int(total_match.group(1))
    else:
        total = passed + failed

    return passed, failed, total


class TestStep:
    """프로젝트 테스트를 실행하는 파이프라인 스텝.

    테스트 자체가 실패하더라도 StepStatus.FAILED를 반환할 뿐
    파이프라인 전체를 중단하지 않는다 (결과만 기록).
    """

    async def run(
        self,
        repo_path: str,
        language: str,
    ) -> StepResult:
        """
        언어에 맞는 테스트 명령을 실행한다.

        - python: ``pytest --tb=short -q`` (pytest 없으면 SKIPPED)
        - node:   ``npm test``             (test 스크립트 없으면 SKIPPED)
        - 그 외:  SKIPPED

        테스트 실패(returncode != 0)는 파이프라인을 중단하지 않으며
        StepStatus.FAILED + 결과 메타데이터를 반환한다.

        Args:
            repo_path: 클론된 저장소 절대 경로.
            language:  감지된 언어.

        Returns:
            StepResult.
            metadata 키:
                - passed (int)
                - failed (int)
                - total  (int)
                - log    (str)
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

        if language == "python":
            return await self._run_pytest(repo_path, started_at)

        if language == "node":
            return await self._run_npm_test(repo_path, started_at)

        if language == "php":
            return await self._run_php_test(repo_path, started_at)

        skip_reason = f"Test execution for language '{language}' is not supported; skipping"
        logger.info("TestStep SKIPPED: %s", skip_reason)
        return StepResult(
            type=_STEP_TYPE,
            status=StepStatus.SKIPPED,
            log=skip_reason,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
        )

    async def _run_php_test(self, repo_path: str, started_at: datetime) -> StepResult:
        """phpunit 또는 composer test를 실행한다. 둘 다 없으면 SKIPPED."""
        # phpunit 실행 가능 여부 확인
        check = subprocess.run(
            ["php", "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if check.returncode != 0:
            reason = "php not available; skipping test step"
            logger.info("TestStep SKIPPED (php): %s", reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )
        # phpunit 또는 composer test 시도
        if os.path.isfile(os.path.join(repo_path, "phpunit.xml")):
            logger.info("TestStep: running phpunit in %s", repo_path)
            returncode, output = _run(["phpunit"], cwd=repo_path)
        elif os.path.isfile(os.path.join(repo_path, "composer.json")):
            logger.info("TestStep: running composer test in %s", repo_path)
            returncode, output = _run(["composer", "test"], cwd=repo_path)
        else:
            reason = "No phpunit.xml or composer.json found; skipping php test step"
            logger.info("TestStep SKIPPED (php): %s", reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )
        finished_at = datetime.now(tz=timezone.utc)
        status = StepStatus.SUCCESS if returncode == 0 else StepStatus.FAILED
        return StepResult(
            type=_STEP_TYPE,
            status=status,
            log=output,
            started_at=started_at,
            finished_at=finished_at,
            metadata={"test_command": "phpunit or composer test"},
        )

    # ------------------------------------------------------------------
    # 언어별 실행 메서드
    # ------------------------------------------------------------------

    async def _run_pytest(
        self, repo_path: str, started_at: datetime
    ) -> StepResult:
        """pytest를 실행한다. pytest가 설치되어 있지 않으면 SKIPPED."""
        # pytest 실행 가능 여부 확인
        check = subprocess.run(
            ["python", "-m", "pytest", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if check.returncode != 0:
            reason = "pytest not available; skipping test step"
            logger.info("TestStep SKIPPED (python): %s", reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )

        logger.info("TestStep: running pytest in %s", repo_path)
        returncode, output = _run(
            ["python", "-m", "pytest", "--tb=short", "-q"], cwd=repo_path
        )
        finished_at = datetime.now(tz=timezone.utc)

        passed, failed, total = _parse_pytest_output(output)
        status = StepStatus.SUCCESS if returncode == 0 else StepStatus.FAILED

        logger.info(
            "TestStep (pytest): status=%s passed=%d failed=%d total=%d",
            status.value,
            passed,
            failed,
            total,
        )
        return StepResult(
            type=_STEP_TYPE,
            status=status,
            log=output,
            started_at=started_at,
            finished_at=finished_at,
            error=("pytest exited with non-zero status" if returncode != 0 else ""),
            metadata={"passed": passed, "failed": failed, "total": total},
        )

    async def _run_npm_test(
        self, repo_path: str, started_at: datetime
    ) -> StepResult:
        """npm test를 실행한다. test 스크립트가 없으면 SKIPPED."""
        import json

        pkg_json_path = os.path.join(repo_path, "package.json")
        if not os.path.isfile(pkg_json_path):
            reason = "package.json not found; skipping npm test"
            logger.info("TestStep SKIPPED (node): %s", reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )

        try:
            with open(pkg_json_path, encoding="utf-8") as fh:
                pkg_data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            pkg_data = {}

        scripts = pkg_data.get("scripts", {})
        if "test" not in scripts:
            reason = "No 'test' script in package.json; skipping npm test"
            logger.info("TestStep SKIPPED (node): %s", reason)
            return StepResult(
                type=_STEP_TYPE,
                status=StepStatus.SKIPPED,
                log=reason,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
            )

        logger.info("TestStep: running npm test in %s", repo_path)
        returncode, output = _run(["npm", "test", "--", "--watchAll=false"], cwd=repo_path)
        finished_at = datetime.now(tz=timezone.utc)

        passed, failed, total = _parse_npm_test_output(output)
        status = StepStatus.SUCCESS if returncode == 0 else StepStatus.FAILED

        logger.info(
            "TestStep (npm test): status=%s passed=%d failed=%d total=%d",
            status.value,
            passed,
            failed,
            total,
        )
        return StepResult(
            type=_STEP_TYPE,
            status=status,
            log=output,
            started_at=started_at,
            finished_at=finished_at,
            error=("npm test exited with non-zero status" if returncode != 0 else ""),
            metadata={"passed": passed, "failed": failed, "total": total},
        )
