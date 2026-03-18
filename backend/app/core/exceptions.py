class PipelineException(Exception):
    """파이프라인 실행 중 발생하는 예외."""

    def __init__(self, message: str, pipeline_id: str | None = None) -> None:
        self.message = message
        self.pipeline_id = pipeline_id
        super().__init__(self.message)


class StepException(Exception):
    """파이프라인 스텝 실행 중 발생하는 예외."""

    def __init__(
        self,
        message: str,
        step_type: str | None = None,
        pipeline_id: str | None = None,
    ) -> None:
        self.message = message
        self.step_type = step_type
        self.pipeline_id = pipeline_id
        super().__init__(self.message)


class SecurityScanException(Exception):
    """보안 스캔 도구(Semgrep 등) 실행 중 발생하는 예외."""

    def __init__(self, message: str, tool: str | None = None) -> None:
        self.message = message
        self.tool = tool
        super().__init__(self.message)


class RepositoryCloneException(Exception):
    """GitHub 저장소 클론 중 발생하는 예외."""

    def __init__(self, message: str, github_url: str | None = None) -> None:
        self.message = message
        self.github_url = github_url
        super().__init__(self.message)


class NVDAPIException(Exception):
    """NVD API 호출 중 발생하는 예외."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)
