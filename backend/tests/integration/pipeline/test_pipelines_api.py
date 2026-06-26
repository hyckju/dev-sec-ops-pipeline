"""파이프라인 API 계약(contract) 테스트.

CI/CD 통합에서 외부 GitHub Action이 의존할 응답 스키마/상태 코드를 고정한다.
DB는 AsyncMock으로 대체하고, PipelineService.create_and_run은 stub하여
백그라운드 태스크 없이 라우터의 입출력 계약만 검증한다.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_db
from app.core.config import settings
from app.core.constants import PipelineStatus, Severity
from app.db.models.pipeline import Pipeline
from app.main import app
from app.services.pipeline.pipeline_service import PipelineService


# ── 공통 fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def mock_db_session() -> AsyncMock:
    """get_db 오버라이드용 더미 AsyncSession."""
    session = AsyncMock()
    return session


@pytest.fixture
def override_db(mock_db_session):
    """FastAPI dependency_overrides로 get_db를 mock 세션으로 교체."""

    async def _override():
        yield mock_db_session

    app.dependency_overrides[get_db] = _override
    yield mock_db_session
    app.dependency_overrides.clear()


@pytest.fixture
async def client(override_db):
    """ASGITransport 기반 in-memory httpx 클라이언트 (lifespan 미실행)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _stub_pipeline() -> Pipeline:
    """create_and_run이 반환할 가짜 Pipeline 인스턴스."""
    p = Pipeline()
    p.id = uuid.uuid4()
    p.project_id = uuid.uuid4()
    p.status = PipelineStatus.PENDING
    p.branch = None
    p.commit_sha = None
    p.steps = []
    p.started_at = None
    p.finished_at = None
    p.created_at = datetime.now(timezone.utc)
    return p


def _stub_vuln(severity: Severity, cve_id: str | None = None):
    """VulnerabilityResponse.model_validate가 읽을 수 있는 가짜 Vulnerability 객체."""
    v = MagicMock()
    v.id = uuid.uuid4()
    v.pipeline_id = uuid.uuid4()
    v.cve_id = cve_id
    v.severity = severity
    v.title = "stub vuln"
    v.description = None
    v.file_path = None
    v.line_number = None
    v.rule_id = None
    v.created_at = datetime.now(timezone.utc)
    v.raw_output = None
    v.kev_listed = False
    return v


# ── POST /api/v1/pipelines/ — 정상 케이스 ─────────────────────────────


async def test_post_pipeline_returns_202_and_response_shape(client, monkeypatch):
    """정상 요청은 202와 PipelineResponse 스키마를 반환해야 한다 (CI 폴링용 id 필수)."""
    fake = _stub_pipeline()

    async def _fake_create_and_run(self, github_url, db, cwes=None, fields=None, changed_files=None):
        return fake

    monkeypatch.setattr(PipelineService, "create_and_run", _fake_create_and_run)

    resp = await client.post(
        "/api/v1/pipelines/",
        json={"github_url": "https://github.com/WebGoat/WebGoat"},
    )

    assert resp.status_code == 202
    body = resp.json()
    # CI/CD 통합에서 GitHub Action이 의존할 핵심 필드
    assert body["id"] == str(fake.id)
    assert body["status"] == "pending"
    assert "project_id" in body
    assert "created_at" in body
    assert body["branch"] is None
    assert body["commit_sha"] is None


async def test_post_pipeline_forwards_selected_cwe_ids(client, monkeypatch):
    """요청의 selected_cwe_ids가 서비스 레이어로 그대로 전달되어야 한다."""
    captured: dict = {}

    async def _capture(self, github_url, db, cwes=None, fields=None, changed_files=None):
        captured["github_url"] = github_url
        captured["cwes"] = cwes
        captured["fields"] = fields
        captured["changed_files"] = changed_files
        return _stub_pipeline()

    monkeypatch.setattr(PipelineService, "create_and_run", _capture)

    await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/example/repo",
            "selected_cwe_ids": ["CWE-89", "CWE-79"],
            "selected_cve_fields": ["cve_id", "cwe"],
        },
    )

    assert captured["github_url"] == "https://github.com/example/repo"
    assert captured["cwes"] == ["CWE-89", "CWE-79"]
    assert captured["fields"] == ["cve_id", "cwe"]
    # changed_files 미지정 시 None(=전수 스캔)
    assert captured["changed_files"] is None


# ── POST /api/v1/pipelines/ — 검증 실패 (CI 스크립트 작성자가 알아야 할 422) ─


async def test_post_pipeline_rejects_non_http_url(client):
    """github_url이 HttpUrl 형식이 아니면 422."""
    resp = await client.post(
        "/api/v1/pipelines/",
        json={"github_url": "not-a-url"},
    )
    assert resp.status_code == 422


async def test_post_pipeline_rejects_empty_cve_fields(client):
    """selected_cve_fields가 빈 리스트면 422 (validator: 최소 1개)."""
    resp = await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/x/y",
            "selected_cve_fields": [],
        },
    )
    assert resp.status_code == 422


async def test_post_pipeline_rejects_too_many_cve_fields(client):
    """selected_cve_fields가 5개 이상이면 422 (validator: 최대 4개)."""
    resp = await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/x/y",
            "selected_cve_fields": [
                "cve_id", "cwe", "cvss_score", "kev_listed", "cpe_list"
            ],
        },
    )
    assert resp.status_code == 422


async def test_post_pipeline_rejects_unknown_cve_field(client):
    """selected_cve_fields에 정의되지 않은 값이 있으면 422 (Enum 검증)."""
    resp = await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/x/y",
            "selected_cve_fields": ["definitely_not_a_field"],
        },
    )
    assert resp.status_code == 422


async def test_post_pipeline_deduplicates_cve_fields(client, monkeypatch):
    """validator가 중복 cve_field를 제거(순서 유지)하여 서비스에 전달해야 한다."""
    captured: dict = {}

    async def _capture(self, github_url, db, cwes=None, fields=None, changed_files=None):
        captured["fields"] = fields
        return _stub_pipeline()

    monkeypatch.setattr(PipelineService, "create_and_run", _capture)

    await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/x/y",
            "selected_cve_fields": ["cve_id", "cwe", "cve_id", "cwe"],
        },
    )

    assert captured["fields"] == ["cve_id", "cwe"]


async def test_post_pipeline_forwards_changed_files(client, monkeypatch):
    """changed_files(선택적 분석)가 서비스 레이어로 그대로 전달되어야 한다."""
    captured: dict = {}

    async def _capture(self, github_url, db, cwes=None, fields=None, changed_files=None):
        captured["changed_files"] = changed_files
        return _stub_pipeline()

    monkeypatch.setattr(PipelineService, "create_and_run", _capture)

    await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/example/repo",
            "changed_files": ["src/app/main.py", "src/app/db.py"],
        },
    )

    assert captured["changed_files"] == ["src/app/main.py", "src/app/db.py"]


async def test_post_pipeline_normalizes_blank_changed_files_to_none(client, monkeypatch):
    """공백/빈 문자열만 있는 changed_files는 None(=전수 스캔)으로 환원되어야 한다."""
    captured: dict = {}

    async def _capture(self, github_url, db, cwes=None, fields=None, changed_files=None):
        captured["changed_files"] = changed_files
        return _stub_pipeline()

    monkeypatch.setattr(PipelineService, "create_and_run", _capture)

    await client.post(
        "/api/v1/pipelines/",
        json={
            "github_url": "https://github.com/example/repo",
            "changed_files": ["", "   "],
        },
    )

    assert captured["changed_files"] is None


# ── GET /api/v1/pipelines/ — 목록 ──────────────────────────────────────


async def test_list_pipelines_returns_empty_array_when_none(client, override_db):
    """파이프라인이 없으면 빈 배열을 반환해야 한다."""
    result_mock = MagicMock()
    result_mock.scalars.return_value.all.return_value = []
    override_db.execute = AsyncMock(return_value=result_mock)

    resp = await client.get("/api/v1/pipelines/")
    assert resp.status_code == 200
    assert resp.json() == []


# ── GET /api/v1/pipelines/{id} — 단일 조회 ────────────────────────────


async def test_get_pipeline_returns_404_for_missing(client, override_db):
    """존재하지 않는 파이프라인 ID는 404 + detail 메시지."""
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    override_db.execute = AsyncMock(return_value=result_mock)

    missing_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/pipelines/{missing_id}")

    assert resp.status_code == 404
    body = resp.json()
    assert "detail" in body
    assert str(missing_id) in body["detail"]


async def test_get_pipeline_rejects_malformed_uuid(client):
    """UUID 형식이 아닌 path param은 FastAPI가 422로 거부해야 한다."""
    resp = await client.get("/api/v1/pipelines/not-a-uuid")
    assert resp.status_code == 422


# ── GET /api/v1/pipelines/{id}/vulnerabilities — 필터 파라미터 ────────


async def test_get_vulnerabilities_returns_404_when_pipeline_missing(client, override_db):
    """파이프라인 자체가 없으면 vulnerabilities 조회도 404."""
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    override_db.execute = AsyncMock(return_value=result_mock)

    missing_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/pipelines/{missing_id}/vulnerabilities")
    assert resp.status_code == 404


async def test_get_vulnerabilities_rejects_min_cvss_out_of_range(client):
    """min_cvss는 0.0~10.0 범위. 11.0 같은 값은 422."""
    pipeline_id = uuid.uuid4()
    resp = await client.get(
        f"/api/v1/pipelines/{pipeline_id}/vulnerabilities",
        params={"min_cvss": 11.0},
    )
    assert resp.status_code == 422


async def test_get_vulnerabilities_accepts_valid_filter_params(client, override_db):
    """severity/cwe_id/kev_only/sort_by/sort_order 모두 허용되어야 한다."""
    # 파이프라인 존재 + 빈 vuln 리스트 시나리오
    pipeline_mock = MagicMock(spec=Pipeline)
    first_result = MagicMock()
    first_result.scalar_one_or_none.return_value = pipeline_mock

    second_result = MagicMock()
    second_result.scalars.return_value.all.return_value = []

    override_db.execute = AsyncMock(side_effect=[first_result, second_result])

    pipeline_id = uuid.uuid4()
    resp = await client.get(
        f"/api/v1/pipelines/{pipeline_id}/vulnerabilities",
        params={
            "severity": "high",
            "cwe_id": "CWE-89",
            "min_cvss": 7.0,
            "sort_by": "cvss_score",
            "sort_order": "desc",
            "kev_only": "true",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ── GET /api/v1/pipelines/{id}/status — 가벼운 폴링 ───────────────────


async def test_get_status_returns_404_for_missing(client, override_db):
    """존재하지 않는 파이프라인 status 조회는 404."""
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    override_db.execute = AsyncMock(return_value=result_mock)

    missing_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/pipelines/{missing_id}/status")
    assert resp.status_code == 404


async def test_get_status_returns_progress_shape_without_vulnerabilities(client, override_db):
    """status는 진행 단계 + 취약점 수만 반환하고 vulnerabilities를 직렬화하지 않아야 한다."""
    pipeline = _stub_pipeline()
    pipeline.status = PipelineStatus.RUNNING
    pipeline.steps = [{"type": "clone"}, {"type": "security_scan"}]

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    count_result = MagicMock()
    count_result.scalar_one.return_value = 5
    override_db.execute = AsyncMock(side_effect=[pipeline_result, count_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}/status")

    assert resp.status_code == 200
    body = resp.json()
    # CI 폴링이 의존하는 핵심 필드
    assert body["id"] == str(pipeline.id)
    assert body["status"] == "running"
    assert body["current_step"] == "security_scan"  # steps[-1]["type"]
    assert body["completed_steps"] == 2
    assert body["total_steps"] == 6
    assert body["vulnerability_count"] == 5
    # 가벼움 보장 — 전체 취약점 목록은 포함하지 않는다
    assert "vulnerabilities" not in body


async def test_get_status_current_step_none_when_no_steps(client, override_db):
    """steps가 비어 있으면 current_step은 None, completed_steps는 0이어야 한다."""
    pipeline = _stub_pipeline()
    pipeline.steps = []

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    override_db.execute = AsyncMock(side_effect=[pipeline_result, count_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}/status")

    assert resp.status_code == 200
    body = resp.json()
    assert body["current_step"] is None
    assert body["completed_steps"] == 0
    assert body["vulnerability_count"] == 0


# ── GET /api/v1/pipelines/{id} — summary 집계 + KEV 주입 ──────────────


async def test_get_pipeline_summary_counts_and_kev(client, override_db):
    """summary는 심각도별 카운트(합 == vulnerabilities 길이) + KEV 수를 집계해야 한다."""
    pipeline = _stub_pipeline()
    pipeline.vulnerabilities = [
        _stub_vuln(Severity.CRITICAL, cve_id="CVE-1"),
        _stub_vuln(Severity.HIGH, cve_id="CVE-2"),
        _stub_vuln(Severity.MEDIUM, cve_id=None),
    ]

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    # _build_vuln_responses의 KEV 조인 — CVE-1만 KEV 등재
    kev_result = MagicMock()
    kev_result.all.return_value = [("CVE-1",)]
    override_db.execute = AsyncMock(side_effect=[pipeline_result, kev_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}")

    assert resp.status_code == 200
    body = resp.json()
    summary = body["summary"]
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 0
    assert summary["info"] == 0
    # 심각도 카운트 합 == 취약점 수
    sev_total = sum(summary[k] for k in ("critical", "high", "medium", "low", "info"))
    assert sev_total == len(body["vulnerabilities"]) == 3
    # KEV 주입 — CVE-1 1건만
    assert summary["kev_count"] == 1


# ── 인증 (verify_api_key) — settings.API_KEY 활성 시 ─────────────────


async def test_auth_rejects_when_key_set_and_header_missing(client, override_db, monkeypatch):
    """API_KEY 설정 시 X-API-Key 헤더 없는 요청은 401 (기존 테스트는 키 미설정이라 영향 없음)."""
    monkeypatch.setattr(settings, "API_KEY", "secret-key")
    resp = await client.get("/api/v1/pipelines/")
    assert resp.status_code == 401


async def test_auth_passes_when_header_matches(client, override_db, monkeypatch):
    """API_KEY 설정 + 헤더 일치 시 정상 통과(200)해야 한다."""
    monkeypatch.setattr(settings, "API_KEY", "secret-key")
    result_mock = MagicMock()
    result_mock.scalars.return_value.all.return_value = []
    override_db.execute = AsyncMock(return_value=result_mock)

    resp = await client.get("/api/v1/pipelines/", headers={"X-API-Key": "secret-key"})
    assert resp.status_code == 200
