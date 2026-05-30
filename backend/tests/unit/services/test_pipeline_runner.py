"""PipelineRunner.run 오케스트레이션 단위 테스트.

검증 영역:
- clone 실패 → 즉시 중단 (이후 step 미실행, FAILED finalize)
- install/test 실패 → 보안 스캔까지 계속 진행 (치명적 아님)
- security_scan 실패 → 중단 (build/report 미실행, FAILED finalize)
- build 실패 → report는 그래도 실행 (전체 status는 FAILED)
- 정상 경로 → 6 step 모두 실행 + vulnerabilities 저장 + SUCCESS finalize
- pipeline 미존재 → 어떤 부수효과도 없이 조기 return
- 잘못된 UUID 포맷 → _fetch_pipeline이 None 반환
- 스텝 내부 예외 → FAILED로 finalize + workspace cleanup 보장
- workspace cleanup은 finally에서 항상 호출 (성공/실패 무관)

전제: StepExecutor.execute, detectors, tempfile/shutil 부수효과는 모두 mock한다.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.constants import PipelineStatus, StepStatus, StepType

# SQLAlchemy 매퍼가 모든 relationship target 클래스를 알 수 있도록
# Pipeline import 전에 의존 모델을 모두 로드한다.
from app.db.models import project, vulnerability, report, cve_catalog  # noqa: F401
from app.db.models.pipeline import Pipeline
from app.services.pipeline import pipeline_runner as pr_module
from app.services.pipeline.pipeline_runner import PipelineRunner
from app.services.pipeline.step_executor import StepResult


# ── 헬퍼 ───────────────────────────────────────────────────────────────


def _step_result(
    step_type: StepType,
    status: StepStatus = StepStatus.SUCCESS,
    metadata: dict | None = None,
    error: str = "",
) -> StepResult:
    now = datetime.now(tz=timezone.utc)
    return StepResult(
        type=step_type.value,
        status=status,
        log="",
        started_at=now,
        finished_at=now,
        error=error,
        metadata=metadata or {},
    )


def _fake_pipeline() -> Pipeline:
    p = Pipeline()
    p.id = uuid.uuid4()
    p.project_id = uuid.uuid4()
    p.status = PipelineStatus.PENDING
    p.branch = None
    p.commit_sha = None
    p.steps = []
    p.started_at = None
    p.finished_at = None
    return p


def _patch_executor(runner: PipelineRunner, results_by_step: dict[StepType, StepResult]) -> list[StepType]:
    """StepExecutor.execute를 step_type → StepResult 매핑으로 mock하고 호출 순서 기록."""
    call_log: list[StepType] = []

    async def _fake_execute(step_type, context):
        call_log.append(step_type)
        return results_by_step.get(step_type, _step_result(step_type))

    runner._executor.execute = AsyncMock(side_effect=_fake_execute)
    return call_log


# ── fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def db_session() -> AsyncMock:
    """flush()/execute()만 awaitable이면 충분한 더미 세션."""
    session = AsyncMock()
    session.add = MagicMock()  # SQLAlchemy add는 동기
    return session


@pytest.fixture
def fake_pipeline() -> Pipeline:
    return _fake_pipeline()


@pytest.fixture
def runner(monkeypatch, fake_pipeline):
    """detectors / tempfile / shutil / _fetch_pipeline / _save_vulnerabilities / console 패치된 runner."""
    r = PipelineRunner()

    # 외부 부수효과 차단
    monkeypatch.setattr(pr_module.tempfile, "mkdtemp", MagicMock(return_value="/tmp/fake-workspace"))
    monkeypatch.setattr(pr_module.shutil, "rmtree", MagicMock())
    monkeypatch.setattr(pr_module.os.path, "isdir", lambda _p: True)
    monkeypatch.setattr(pr_module, "detect_project_root", lambda p: p)
    monkeypatch.setattr(pr_module, "detect_language", lambda _p: "python")
    monkeypatch.setattr(pr_module, "detect_package_manager", lambda _p, _l: "pip")
    monkeypatch.setattr(pr_module, "console", MagicMock())

    # _fetch_pipeline은 의도한 pipeline을 반환 (실제 DB 조회 우회)
    async def _fake_fetch(self, pipeline_id, db):
        return fake_pipeline

    monkeypatch.setattr(PipelineRunner, "_fetch_pipeline", _fake_fetch)

    # _save_vulnerabilities는 호출 인자만 추적 (별도 단위 검증 대상이 아님)
    save_calls: list[tuple] = []

    async def _fake_save(self, pipeline_id, vulnerabilities, db):
        save_calls.append((pipeline_id, list(vulnerabilities), db))

    monkeypatch.setattr(PipelineRunner, "_save_vulnerabilities", _fake_save)
    r.save_calls = save_calls

    return r


# ── 정상 경로 ──────────────────────────────────────────────────────────


async def test_run_executes_all_six_steps_in_order_on_success(runner, fake_pipeline, db_session):
    """모든 step이 SUCCESS면 6 step 전부, 정해진 순서로 호출되어야 한다."""
    results = {
        StepType.CLONE: _step_result(
            StepType.CLONE,
            metadata={"repo_path": "/repo", "commit_sha": "abc123", "branch": "main"},
        ),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
        StepType.REPORT: _step_result(StepType.REPORT, metadata={"report_text": ""}),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert call_log == [
        StepType.CLONE,
        StepType.INSTALL,
        StepType.TEST,
        StepType.SECURITY_SCAN,
        StepType.BUILD,
        StepType.REPORT,
    ]
    assert fake_pipeline.status == PipelineStatus.SUCCESS
    assert fake_pipeline.finished_at is not None
    assert fake_pipeline.started_at is not None


async def test_run_propagates_clone_metadata_to_pipeline(runner, fake_pipeline, db_session):
    """clone metadata의 commit_sha/branch가 pipeline 컬럼에 저장되어야 한다."""
    results = {
        StepType.CLONE: _step_result(
            StepType.CLONE,
            metadata={"repo_path": "/repo", "commit_sha": "deadbeef", "branch": "feature/x"},
        ),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
    }
    _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert fake_pipeline.commit_sha == "deadbeef"
    assert fake_pipeline.branch == "feature/x"


async def test_run_saves_vulnerabilities_from_security_scan(runner, fake_pipeline, db_session):
    """security_scan metadata의 vulnerabilities가 _save_vulnerabilities로 그대로 전달되어야 한다."""
    vulns = [
        {"title": "SQLi", "severity": "high"},
        {"title": "XSS", "severity": "medium"},
    ]
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": vulns}
        ),
    }
    _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert len(runner.save_calls) == 1
    saved_pid, saved_vulns, _ = runner.save_calls[0]
    assert saved_pid == str(fake_pipeline.id)
    assert saved_vulns == vulns


# ── clone 실패 → 즉시 중단 ─────────────────────────────────────────────


async def test_run_aborts_immediately_on_clone_failure(runner, fake_pipeline, db_session):
    """clone이 FAILED면 install 이후 어떤 step도 실행되면 안 된다."""
    results = {
        StepType.CLONE: _step_result(
            StepType.CLONE, status=StepStatus.FAILED, error="git clone 실패"
        ),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert call_log == [StepType.CLONE]
    assert fake_pipeline.status == PipelineStatus.FAILED
    assert fake_pipeline.finished_at is not None
    assert runner.save_calls == []


# ── install/test 실패 → 보안 스캔까지 진행 (핵심 회귀 방지) ───────────


async def test_run_continues_to_security_scan_after_install_failure(runner, fake_pipeline, db_session):
    """install 실패는 치명적이지 않다 — scan/build/report가 모두 실행되어야 한다."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.INSTALL: _step_result(
            StepType.INSTALL, status=StepStatus.FAILED, error="pip install 실패"
        ),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert StepType.SECURITY_SCAN in call_log
    assert StepType.BUILD in call_log
    assert StepType.REPORT in call_log
    # install 실패만으로는 전체 status를 FAILED로 만들지 않는다
    assert fake_pipeline.status == PipelineStatus.SUCCESS


async def test_run_continues_to_security_scan_after_test_failure(runner, fake_pipeline, db_session):
    """test 실패도 치명적이지 않다 — scan은 그대로 실행되어야 한다."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.TEST: _step_result(
            StepType.TEST, status=StepStatus.FAILED, error="pytest 실패"
        ),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert StepType.SECURITY_SCAN in call_log
    assert fake_pipeline.status == PipelineStatus.SUCCESS


# ── security_scan 실패 → 중단 ─────────────────────────────────────────


async def test_run_aborts_on_security_scan_failure(runner, fake_pipeline, db_session):
    """security_scan이 FAILED면 build/report는 실행되지 않고 FAILED로 finalize."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, status=StepStatus.FAILED, error="semgrep 인증 오류"
        ),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert StepType.BUILD not in call_log
    assert StepType.REPORT not in call_log
    assert fake_pipeline.status == PipelineStatus.FAILED
    assert fake_pipeline.finished_at is not None


# ── build 실패해도 report는 실행 ──────────────────────────────────────


async def test_run_runs_report_even_when_build_fails(runner, fake_pipeline, db_session):
    """build 실패는 전체 status를 FAILED로 만들지만, report는 그래도 작성되어야 한다."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
        StepType.BUILD: _step_result(
            StepType.BUILD, status=StepStatus.FAILED, error="빌드 실패"
        ),
        StepType.REPORT: _step_result(StepType.REPORT, metadata={"report_text": ""}),
    }
    call_log = _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert StepType.REPORT in call_log
    assert fake_pipeline.status == PipelineStatus.FAILED


# ── finalize / workspace cleanup 보장 ─────────────────────────────────


async def test_run_cleans_up_workspace_on_success(runner, fake_pipeline, db_session):
    """정상 경로에서도 workspace는 finally에서 정리되어야 한다."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, metadata={"repo_path": "/repo"}),
        StepType.SECURITY_SCAN: _step_result(
            StepType.SECURITY_SCAN, metadata={"vulnerabilities": []}
        ),
    }
    _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    pr_module.shutil.rmtree.assert_called_once_with("/tmp/fake-workspace", ignore_errors=True)


async def test_run_cleans_up_workspace_on_clone_failure(runner, fake_pipeline, db_session):
    """clone 실패로 조기 return해도 finally의 cleanup은 실행되어야 한다."""
    results = {
        StepType.CLONE: _step_result(StepType.CLONE, status=StepStatus.FAILED),
    }
    _patch_executor(runner, results)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    pr_module.shutil.rmtree.assert_called_once()


async def test_run_finalizes_and_cleans_up_when_step_raises(runner, fake_pipeline, db_session):
    """스텝 내부에서 예외 발생 시 FAILED로 finalize되고 workspace cleanup이 호출되어야 한다."""

    async def _boom(step_type, context):
        if step_type == StepType.SECURITY_SCAN:
            raise RuntimeError("예기치 못한 오류")
        return _step_result(
            step_type,
            metadata={"repo_path": "/repo"} if step_type == StepType.CLONE else {},
        )

    runner._executor.execute = AsyncMock(side_effect=_boom)

    await runner.run(str(fake_pipeline.id), "https://github.com/o/r", db_session)

    assert fake_pipeline.status == PipelineStatus.FAILED
    assert fake_pipeline.finished_at is not None
    pr_module.shutil.rmtree.assert_called_once()
    # 예외가 steps 배열에 runner_error 엔트리로 기록되어야 함
    assert any(s.get("type") == "runner_error" for s in (fake_pipeline.steps or []))


# ── pipeline 미존재 / 잘못된 UUID ─────────────────────────────────────


async def test_run_returns_early_when_pipeline_not_found(monkeypatch, db_session):
    """_fetch_pipeline이 None을 반환하면 어떤 부수효과도 일어나지 않는다."""
    r = PipelineRunner()
    r._executor.execute = AsyncMock()
    mkdtemp_mock = MagicMock()
    monkeypatch.setattr(pr_module.tempfile, "mkdtemp", mkdtemp_mock)
    monkeypatch.setattr(pr_module, "console", MagicMock())

    async def _none_fetch(self, pipeline_id, db):
        return None

    monkeypatch.setattr(PipelineRunner, "_fetch_pipeline", _none_fetch)

    await r.run(str(uuid.uuid4()), "https://github.com/o/r", db_session)

    r._executor.execute.assert_not_called()
    mkdtemp_mock.assert_not_called()


async def test_fetch_pipeline_returns_none_for_invalid_uuid(db_session):
    """UUID 파싱 실패는 None 반환으로 흡수해야 한다 (ValueError 전파 금지)."""
    r = PipelineRunner()
    result = await r._fetch_pipeline("not-a-uuid", db_session)
    assert result is None
