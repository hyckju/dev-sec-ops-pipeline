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


class PipelineDetailResponse(PipelineResponse):
    vulnerabilities: list["VulnerabilityResponse"] = []


from app.schemas.vulnerability import VulnerabilityResponse  # noqa: E402
PipelineDetailResponse.model_rebuild()
