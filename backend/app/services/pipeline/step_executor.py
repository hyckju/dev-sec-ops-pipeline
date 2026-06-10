"""파이프라인 스텝 실행 결과 데이터 클래스 및 스텝 실행기."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.constants import StepStatus, StepType

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """
    파이프라인 각 스텝의 실행 결과를 담는 데이터 클래스.

    Attributes:
        type:        스텝 타입 식별자 (StepType 값).
        status:      실행 결과 상태 (StepStatus 값).
        log:         실행 중 수집된 stdout/stderr 로그.
        started_at:  스텝 시작 시각 (UTC).
        finished_at: 스텝 종료 시각 (UTC).
        error:       오류 발생 시 오류 메시지.
        metadata:    스텝별 부가 데이터 (예: repo_path, commit_sha 등).
    """

    type: str
    status: StepStatus
    log: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """JSON 직렬화 가능한 dict로 변환한다 (Pipeline.steps 컬럼 저장용)."""
        return {
            "type": self.type,
            "status": self.status.value if isinstance(self.status, StepStatus) else self.status,
            "log": self.log,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "error": self.error,
            "metadata": self.metadata,
        }


class StepExecutor:
    """
    StepType에 맞는 스텝 클래스를 선택하여 실행하는 오케스트레이터.

    각 스텝은 context dict를 공유하며, 실행 결과(StepResult)를 반환한다.
    context에는 파이프라인 전반에서 필요한 상태값
    (repo_path, language, pipeline_id 등)을 담는다.
    """

    async def execute(self, step_type: StepType, context: dict) -> StepResult:
        """
        지정한 step_type에 대응하는 스텝을 실행하고 StepResult를 반환한다.

        Args:
            step_type: 실행할 스텝의 타입 (StepType 열거형).
            context:   파이프라인 공유 컨텍스트 dict.
                       읽기/쓰기가 모두 가능하며 스텝 간 상태를 전달한다.
                       공통 키:
                         - github_url (str)
                         - workspace_dir (str)
                         - repo_path (str)       ← clone 이후 채워짐
                         - language (str)        ← detect 이후 채워짐
                         - package_manager (str) ← detect 이후 채워짐
                         - pipeline_id (str)
                         - cve_list (list[dict]) ← security_scan 전 채워짐

        Returns:
            StepResult 인스턴스.
        """
        started_at = datetime.now(tz=timezone.utc)
        logger.info("StepExecutor: starting step '%s'", step_type.value)

        try:
            result = await self._dispatch(step_type, context)
        except Exception as exc:
            finished_at = datetime.now(tz=timezone.utc)
            logger.exception(
                "StepExecutor: unhandled exception in step '%s'", step_type.value
            )
            return StepResult(
                type=step_type.value,
                status=StepStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                error=str(exc),
            )

        # started_at / finished_at 이 스텝 내부에서 설정되지 않았다면 여기서 채운다
        if result.started_at is None:
            result.started_at = started_at
        if result.finished_at is None:
            result.finished_at = datetime.now(tz=timezone.utc)

        logger.info(
            "StepExecutor: step '%s' finished with status '%s'",
            step_type.value,
            result.status.value,
        )
        return result

    # ------------------------------------------------------------------
    # 내부 디스패치 메서드
    # ------------------------------------------------------------------

    async def _dispatch(self, step_type: StepType, context: dict) -> StepResult:
        """step_type에 따라 알맞은 스텝 클래스를 인스턴스화하고 실행한다."""
        if step_type == StepType.CLONE:
            from app.services.pipeline.steps.clone_step import CloneStep
            return await CloneStep().run(
                github_url=context.get("github_url", ""),
                workspace_dir=context.get("workspace_dir", ""),
                pipeline_id=context.get("pipeline_id", ""),
            )

        if step_type == StepType.INSTALL:
            # 디펜던시 설치 건너뜀
            return StepResult(
                type=step_type.value,
                status=StepStatus.SKIPPED,
                log="Dependency install skipped.",
                error="Dependency install skipped.",
            )

        if step_type == StepType.TEST:
            # 테스트 건너뜀
            return StepResult(
                type=step_type.value,
                status=StepStatus.SKIPPED,
                log="Test step skipped.",
                error="Test step skipped.",
            )

        if step_type == StepType.SECURITY_SCAN:
            from app.services.pipeline.steps.security_scan_step import SecurityScanStep
            return await SecurityScanStep().run(
                repo_path=context.get("repo_path", ""),
                language=context.get("language", "unknown"),
                cve_list=context.get("cve_list", []),
                selected_cwe_ids=context.get("selected_cwe_ids", ["CWE-89"]),
                cve_map=context.get("cve_map", None),
                github_url=context.get("github_url", ""),
                cve_service=context.get("cve_service"),
                db=context.get("db"),
                changed_files=context.get("changed_files"),
                repo_root_path=context.get("repo_root_path", ""),
            )

        if step_type == StepType.BUILD:
            # 빌드 건너뜀
            return StepResult(
                type=step_type.value,
                status=StepStatus.SKIPPED,
                log="Build step skipped.",
                error="Build step skipped.",
            )

        if step_type == StepType.REPORT:
            from app.services.pipeline.steps.report_step import ReportStep
            return await ReportStep().run(
                pipeline_id=context.get("pipeline_id", ""),
                vulnerabilities=context.get("vulnerabilities", []),
                step_results=context.get("step_results", []),
                selected_cwe_ids=context.get("selected_cwe_ids", ["CWE-89"]),
                selected_cve_fields=context.get("selected_cve_fields"),
                github_url=context.get("github_url", ""),
                cwe_scan_times=context.get("cwe_scan_times"),
            )

        # 알 수 없는 스텝 타입
        return StepResult(
            type=step_type.value,
            status=StepStatus.FAILED,
            error=f"Unknown step type: {step_type.value}",
        )
