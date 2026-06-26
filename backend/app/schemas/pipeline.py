from pydantic import BaseModel, Field, HttpUrl, field_validator
import uuid
from datetime import datetime
from app.core.constants import CveField, PipelineStatus

# 선택 가능한 CVE 필드 전체 목록
_ALL_CVE_FIELDS: list[CveField] = list(CveField)
# 기본값: cve_id, cwe, cvss_score, description (4개)
_DEFAULT_CVE_FIELDS: list[CveField] = [
    CveField.CVE_ID,
    CveField.CWE,
    CveField.CVSS_SCORE,
    CveField.DESCRIPTION,
]


class PipelineCreate(BaseModel):
    github_url: HttpUrl
    selected_cwe_ids: list[str] = [
        "CWE-89",   # SQL Injection
        "CWE-79",   # XSS
        "CWE-22",   # Path Traversal
        "CWE-918",  # SSRF
        "CWE-78",   # Command Injection
        "CWE-798",  # Hardcoded API Key / Credentials
    ]
    selected_cve_fields: list[CveField] = Field(
        default=_DEFAULT_CVE_FIELDS,
        description="리포트에 포함할 CVE 정보 필드 (1~4개 선택). "
                    "선택 가능: cve_id, cwe, cvss_score, kev_listed, cpe_list, description",
    )
    changed_files: list[str] | None = Field(
        default=None,
        description="선택적 분석 — 스캔을 이 파일 목록(저장소 루트 기준 상대경로)으로 한정한다. "
                    "GitHub Action이 `git diff --name-only`로 PR 변경분을 전달한다. "
                    "None 또는 빈 목록이면 전수(full) 스캔.",
    )

    @field_validator("changed_files")
    @classmethod
    def _normalize_changed_files(cls, v: list[str] | None) -> list[str] | None:
        """공백/빈 문자열 항목 제거. 모두 비면 None(=전수 스캔)으로 환원."""
        if v is None:
            return None
        cleaned = [f.strip() for f in v if f and f.strip()]
        return cleaned or None

    @field_validator("selected_cve_fields")
    @classmethod
    def _validate_cve_fields(cls, v: list[CveField]) -> list[CveField]:
        if not v:
            raise ValueError("selected_cve_fields는 최소 1개 이상이어야 합니다.")
        if len(v) > 4:
            raise ValueError("selected_cve_fields는 최대 4개까지 선택할 수 있습니다.")
        # 중복 제거 (순서 유지)
        seen: set[CveField] = set()
        deduped: list[CveField] = []
        for f in v:
            if f not in seen:
                seen.add(f)
                deduped.append(f)
        return deduped


class PipelineResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: PipelineStatus
    branch: str | None
    commit_sha: str | None
    steps: list[dict] | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PipelineSummary(BaseModel):
    """심각도별 취약점 집계 + KEV 등재 수 (PR 코멘트/차단 정책 판단용)."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    kev_count: int = 0


class PipelineDetailResponse(PipelineResponse):
    vulnerabilities: list["VulnerabilityResponse"] = []
    summary: PipelineSummary = PipelineSummary()


class PipelineStatusResponse(BaseModel):
    """가벼운 상태 폴링용 응답 (전체 vulnerabilities 직렬화 없음).

    GitHub Action이 30초 간격으로 폴링하며 status/진행 단계/취약점 수만 확인한다.
    """
    id: uuid.UUID
    status: PipelineStatus
    current_step: str | None        # 마지막으로 기록된 스텝 type (없으면 None)
    completed_steps: int            # 기록된 스텝 수 (len(steps))
    total_steps: int = 6
    vulnerability_count: int
    started_at: datetime | None
    finished_at: datetime | None

    model_config = {"from_attributes": True}


from app.schemas.vulnerability import VulnerabilityResponse  # noqa: E402
PipelineDetailResponse.model_rebuild()
