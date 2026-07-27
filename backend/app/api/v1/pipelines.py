import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, verify_api_key
from app.db.models.cve_catalog import CveCatalog
from app.db.models.pipeline import Pipeline
from app.db.models.vulnerability import Vulnerability
from app.schemas.pipeline import (
    PipelineCreate,
    PipelineDetailResponse,
    PipelineResponse,
    PipelineStatusResponse,
    PipelineSummary,
)
from app.schemas.vulnerability import VulnerabilityResponse
from app.services.pipeline.pipeline_service import PipelineService

# 모든 파이프라인 엔드포인트를 verify_api_key로 일괄 보호.
# (projects 라우터/health는 이번 범위 밖 — 추후 필요 시 동일 의존성 적용)
router = APIRouter(dependencies=[Depends(verify_api_key)])

DbDep = Annotated[AsyncSession, Depends(get_db)]

# severity 정렬용 숫자 매핑 (낮을수록 심각)
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


async def _build_vuln_responses(
    db: AsyncSession, vulns
) -> list[VulnerabilityResponse]:
    """Vulnerability ORM 목록을 VulnerabilityResponse로 변환하며 kev_listed를 주입한다.

    cve_id들을 CveCatalog와 조인해 KEV 등재 여부를 채운다.
    get_pipeline(summary 집계용)과 vulnerabilities 엔드포인트가 공유한다.
    """
    all_cve_ids = [v.cve_id for v in vulns if v.cve_id]
    kev_set: set[str] = set()
    if all_cve_ids:
        kev_result = await db.execute(
            select(CveCatalog.cve_id)
            .where(CveCatalog.cve_id.in_(all_cve_ids))
            .where(CveCatalog.kev_listed.is_(True))
        )
        kev_set = {row[0] for row in kev_result.all()}

    responses: list[VulnerabilityResponse] = []
    for vuln in vulns:
        resp = VulnerabilityResponse.model_validate(vuln)
        if vuln.cve_id and vuln.cve_id in kev_set:
            resp = resp.model_copy(update={"kev_listed": True})
        responses.append(resp)
    return responses


def _build_summary(responses: list[VulnerabilityResponse]) -> PipelineSummary:
    """VulnerabilityResponse 목록에서 심각도별 카운트 + KEV 수를 집계한다."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    kev_count = 0
    for resp in responses:
        sev = resp.severity.value
        if sev in counts:
            counts[sev] += 1
        if resp.kev_listed:
            kev_count += 1
    return PipelineSummary(**counts, kev_count=kev_count)


@router.post("/", response_model=PipelineResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_pipeline(body: PipelineCreate, db: DbDep):
    """GitHub URL을 받아 파이프라인을 생성하고 실행한다."""
    service = PipelineService()
    pipeline = await service.create_and_run(
        str(body.github_url),
        db,
        body.selected_cwe_ids,
        [f.value for f in body.selected_cve_fields],
    )
    return pipeline


@router.get("/", response_model=list[PipelineResponse])
async def list_pipelines(db: DbDep, project_id: uuid.UUID | None = None):
    """전체 파이프라인 목록 (project_id 쿼리 파라미터로 필터링 가능, 최신순)"""
    query = select(Pipeline).order_by(Pipeline.created_at.desc())
    if project_id is not None:
        query = query.where(Pipeline.project_id == project_id)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{pipeline_id}", response_model=PipelineDetailResponse)
async def get_pipeline(pipeline_id: uuid.UUID, db: DbDep):
    """파이프라인 상세 조회 (취약점 목록 포함)"""
    result = await db.execute(
        select(Pipeline)
        .options(selectinload(Pipeline.vulnerabilities))
        .where(Pipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pipeline {pipeline_id} not found",
        )

    # KEV 주입 + summary 집계 (vulnerabilities는 selectinload로 이미 로드됨)
    responses = await _build_vuln_responses(db, pipeline.vulnerabilities)
    detail = PipelineDetailResponse.model_validate(pipeline)
    detail.vulnerabilities = responses
    detail.summary = _build_summary(responses)
    return detail


@router.get("/{pipeline_id}/status", response_model=PipelineStatusResponse)
async def get_pipeline_status(pipeline_id: uuid.UUID, db: DbDep):
    """가벼운 상태 폴링 — status + 진행 단계 + 취약점 수만 반환 (CI 폴링용)."""
    result = await db.execute(
        select(Pipeline).where(Pipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pipeline {pipeline_id} not found",
        )

    # 취약점은 직렬화하지 않고 개수만 카운트
    count_result = await db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.pipeline_id == pipeline_id)
    )
    vulnerability_count = count_result.scalar_one()

    steps = pipeline.steps or []
    current_step = steps[-1].get("type") if steps else None

    return PipelineStatusResponse(
        id=pipeline.id,
        status=pipeline.status,
        current_step=current_step,
        completed_steps=len(steps),
        vulnerability_count=vulnerability_count,
        started_at=pipeline.started_at,
        finished_at=pipeline.finished_at,
    )


@router.get("/{pipeline_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def get_pipeline_vulnerabilities(
    pipeline_id: uuid.UUID,
    db: DbDep,
    severity: str | None = Query(default=None, description="심각도 필터 (critical/high/medium/low/info)"),
    cwe_id: str | None = Query(default=None, description="CWE ID 필터 (예: CWE-89)"),
    min_cvss: float | None = Query(default=None, ge=0.0, le=10.0, description="최소 CVSS 점수 (0~10)"),
    sort_by: str = Query(default="severity", description="정렬 기준: severity | cvss_score"),
    sort_order: str = Query(default="desc", description="정렬 방향: desc | asc"),
    kev_only: bool = Query(default=False, description="CISA KEV 등재 취약점만 반환"),
):
    """
    해당 파이프라인의 취약점 목록.

    - **severity**: critical/high/medium/low/info 중 하나로 필터
    - **cwe_id**: CWE-89, CWE-79 등으로 필터
    - **min_cvss**: 지정 점수 이상 CVSS 점수만 반환
    - **sort_by**: severity(기본) 또는 cvss_score 기준 정렬
    - **sort_order**: desc(기본, 심각한 순) 또는 asc
    - **kev_only**: CISA KEV 등재 CVE에 해당하는 항목만 반환
    """
    pipeline_result = await db.execute(
        select(Pipeline).where(Pipeline.id == pipeline_id)
    )
    if pipeline_result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pipeline {pipeline_id} not found",
        )

    # 기본 쿼리 — severity 필터는 DB 레벨에서 처리
    query = select(Vulnerability).where(Vulnerability.pipeline_id == pipeline_id)
    if severity:
        query = query.where(Vulnerability.severity == severity.lower())
    result = await db.execute(query)
    vulns = result.scalars().all()

    # VulnerabilityResponse 변환 + kev_listed 주입 (get_pipeline과 공유)
    responses = await _build_vuln_responses(db, vulns)

    # Python 레벨 필터 (CWE, min_cvss, kev_only)
    filtered: list[VulnerabilityResponse] = []
    for resp in responses:
        if kev_only and not resp.kev_listed:
            continue
        if cwe_id:
            resp_cwe = (resp.detected_cwe or "").upper()
            if not resp_cwe:
                resp_cwe = (resp.cwe or "").upper().split(":")[0].strip()
            if resp_cwe != cwe_id.upper():
                continue
        if min_cvss is not None:
            if resp.cvss_score is None or resp.cvss_score < min_cvss:
                continue
        filtered.append(resp)

    # 정렬
    _order = sort_order.lower()
    if sort_by == "cvss_score":
        filtered.sort(
            key=lambda r: r.cvss_score if r.cvss_score is not None else -1.0,
            reverse=(_order == "desc"),
        )
    else:  # severity 기준 (rank 오름차순 = desc 심각도순)
        filtered.sort(
            key=lambda r: _SEVERITY_RANK.get(r.severity.value, 99),
            reverse=(_order == "asc"),
        )

    return filtered
