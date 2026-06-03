"""GitHub Action 계약(contract) 스냅샷 테스트.

`secscan.yml`(Phase 3)이 curl/jq로 파싱하는 **응답 필드 스키마**를 고정한다.
백엔드 리팩터가 필드명/타입/존재 여부를 바꾸면 Action보다 **먼저** 이 테스트가 깨지도록 한다.

대상 계약(설계 문서 phase-3-github-actions.md "전제 — API 계약" 표):

| 호출 | 메서드 | Action이 jq로 읽는 필드 |
|---|---|---|
| `/api/v1/pipelines/` | POST → 202 | `id` (폴링 키), `status` |
| `/api/v1/pipelines/{id}/status` | GET | `status`, `current_step`, `completed_steps`, `total_steps`, `vulnerability_count` |
| `/api/v1/pipelines/{id}` | GET | `summary.{critical,high,medium,low,info,kev_count}`, `vulnerabilities[]` |

`test_pipelines_api.py`는 *동작*(검증/필터/404)을 테스트한다. 이 파일은 그와 달리
*필드 스키마 자체*를 snapshot으로 못박는 것이 목적이라 별도 파일로 둔다.
픽스처/스텁 패턴(AsyncMock + dependency_overrides)은 동일하게 재사용한다.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_db
from app.core.constants import PipelineStatus, Severity
from app.db.models.pipeline import Pipeline
from app.main import app
from app.services.pipeline.pipeline_service import PipelineService


# ── 공통 fixtures (test_pipelines_api.py와 동일 패턴) ──────────────────


@pytest.fixture
def mock_db_session() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def override_db(mock_db_session):
    async def _override():
        yield mock_db_session

    app.dependency_overrides[get_db] = _override
    yield mock_db_session
    app.dependency_overrides.clear()


@pytest.fixture
async def client(override_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _stub_pipeline() -> Pipeline:
    p = Pipeline()
    p.id = uuid.uuid4()
    p.project_id = uuid.uuid4()
    p.status = PipelineStatus.SUCCESS
    p.branch = None
    p.commit_sha = None
    p.steps = []
    p.started_at = None
    p.finished_at = None
    p.created_at = datetime.now(timezone.utc)
    return p


def _stub_vuln(severity: Severity, cve_id: str | None = None):
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


# ── POST /api/v1/pipelines/ → 202: Action은 .id 로 폴링한다 ───────────


async def test_contract_post_returns_id_and_status(client, monkeypatch):
    """POST 응답에 폴링 키 `id`(uuid 문자열)와 `status`가 반드시 있어야 한다.

    secscan.yml: `id=$(echo "$resp" | jq -r '.id')` → 이 값이 비면 전체 폴링이 깨진다.
    """
    fake = _stub_pipeline()
    fake.status = PipelineStatus.PENDING

    async def _fake_create_and_run(self, github_url, db, cwes=None, fields=None):
        return fake

    monkeypatch.setattr(PipelineService, "create_and_run", _fake_create_and_run)

    resp = await client.post(
        "/api/v1/pipelines/",
        json={"github_url": "https://github.com/WebGoat/WebGoat"},
    )

    assert resp.status_code == 202
    body = resp.json()

    # 필드 존재
    assert "id" in body, "Action 폴링 키 'id' 누락"
    assert "status" in body
    # 타입 계약: id는 uuid 파싱 가능한 문자열 (jq -r '.id'가 쓸 수 있어야 함)
    assert isinstance(body["id"], str)
    uuid.UUID(body["id"])  # 형식 불일치 시 ValueError로 실패
    assert isinstance(body["status"], str)
    assert body["status"] == "pending"


# ── GET /{id}/status: Action 폴링 step이 jq로 읽는 필드 ───────────────


async def test_contract_status_field_schema(client, override_db):
    """폴링 응답 필드 존재 + 타입 + `vulnerabilities` 부재(가벼움) 고정.

    secscan.yml poll step이 jq로 읽는 것: .status .current_step .completed_steps
    .total_steps. 종료 판정은 status ∈ {success,failed,cancelled}.
    """
    pipeline = _stub_pipeline()
    pipeline.status = PipelineStatus.RUNNING
    pipeline.steps = [{"type": "clone"}, {"type": "security_scan"}]

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    count_result = MagicMock()
    count_result.scalar_one.return_value = 7
    override_db.execute = AsyncMock(side_effect=[pipeline_result, count_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}/status")

    assert resp.status_code == 200
    body = resp.json()

    # 필드 존재 — 하나라도 사라지면 Action 폴링이 조용히 오작동
    for key in ("status", "current_step", "completed_steps", "total_steps", "vulnerability_count"):
        assert key in body, f"폴링 계약 필드 '{key}' 누락"

    # 타입 계약
    assert isinstance(body["status"], str)
    assert isinstance(body["completed_steps"], int)
    assert isinstance(body["total_steps"], int)
    assert isinstance(body["vulnerability_count"], int)
    # current_step은 문자열 또는 null (steps가 있으면 마지막 step type)
    assert body["current_step"] is None or isinstance(body["current_step"], str)

    # 가벼움 계약 — 폴링에 전체 취약점 목록을 직렬화하지 않는다
    assert "vulnerabilities" not in body


@pytest.mark.parametrize("terminal", ["success", "failed", "cancelled"])
async def test_contract_status_terminal_values(client, override_db, terminal):
    """status 종료값 3종이 그대로 직렬화되어야 한다 (poll step의 case 분기 키).

    secscan.yml: `case "$status" in success|failed|cancelled) ...` — 이 문자열이
    바뀌면 워크플로가 영원히 폴링하다 timeout(exit 1) 된다.
    """
    pipeline = _stub_pipeline()
    pipeline.status = PipelineStatus(terminal)
    pipeline.steps = [{"type": "report"}]

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    override_db.execute = AsyncMock(side_effect=[pipeline_result, count_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}/status")

    assert resp.status_code == 200
    assert resp.json()["status"] == terminal


# ── GET /{id}: PR 코멘트 step이 읽는 summary 6키 + vulnerabilities[] ──


async def test_contract_detail_summary_six_keys(client, override_db):
    """detail 응답의 `summary`에 6키가 전부 존재(정수)하고 `vulnerabilities`는 배열.

    secscan.yml comment step(github-script)이 읽는 것:
    s.critical s.high s.medium s.low s.info s.kev_count, (d.vulnerabilities||[]).length
    """
    pipeline = _stub_pipeline()
    pipeline.vulnerabilities = [
        _stub_vuln(Severity.CRITICAL, cve_id="CVE-1"),
        _stub_vuln(Severity.HIGH, cve_id="CVE-2"),
    ]

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    kev_result = MagicMock()
    kev_result.all.return_value = [("CVE-1",)]  # CVE-1만 KEV 등재
    override_db.execute = AsyncMock(side_effect=[pipeline_result, kev_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}")

    assert resp.status_code == 200
    body = resp.json()

    # summary 존재 + 6키 전부 존재 + 정수 타입
    assert "summary" in body, "PR 코멘트가 의존하는 'summary' 누락"
    summary = body["summary"]
    for key in ("critical", "high", "medium", "low", "info", "kev_count"):
        assert key in summary, f"summary 계약 키 '{key}' 누락"
        assert isinstance(summary[key], int), f"summary['{key}']는 정수여야 함"

    # vulnerabilities는 항상 배열 (github-script: (d.vulnerabilities||[]).length)
    assert "vulnerabilities" in body
    assert isinstance(body["vulnerabilities"], list)

    # 값 정합성 — 표가 의미를 가지려면 카운트 합 == 취약점 수
    sev_total = sum(summary[k] for k in ("critical", "high", "medium", "low", "info"))
    assert sev_total == len(body["vulnerabilities"])


async def test_contract_detail_summary_present_even_when_no_vulns(client, override_db):
    """취약점 0건이어도 summary 6키는 0으로 존재해야 한다 (코멘트 표가 깨지지 않게)."""
    pipeline = _stub_pipeline()
    pipeline.vulnerabilities = []

    pipeline_result = MagicMock()
    pipeline_result.scalar_one_or_none.return_value = pipeline
    # 취약점이 없으면 _build_vuln_responses가 KEV 조인을 건너뛴다 → execute 1회뿐
    override_db.execute = AsyncMock(side_effect=[pipeline_result])

    resp = await client.get(f"/api/v1/pipelines/{pipeline.id}")

    assert resp.status_code == 200
    summary = resp.json()["summary"]
    assert summary == {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "kev_count": 0,
    }
