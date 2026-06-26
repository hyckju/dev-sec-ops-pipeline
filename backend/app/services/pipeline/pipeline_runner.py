"""파이프라인 전체 실행 오케스트레이터."""

import logging
import os
import shutil
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

from rich.console import Console
from rich.rule import Rule
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import PipelineStatus, StepStatus, StepType
from app.db.models.pipeline import Pipeline
from app.db.models.vulnerability import Vulnerability
from app.services.pipeline.detectors import (
    detect_language,
    detect_package_manager,
    detect_project_root,
)
from app.services.pipeline.step_executor import StepExecutor, StepResult
from app.services.security.cve_service import CVEService

logger = logging.getLogger(__name__)

# 진행 표시줄은 유니코드 글리프(✓ ✗ ⊘)를 출력한다. 일부 Windows 콘솔(cp949 등)은
# 이를 인코딩하지 못해 UnicodeEncodeError를 던지는데, 이 출력은 순수 진행 표시이므로
# 인코딩 실패가 파이프라인 실행을 중단시켜선 안 된다. stdout을 utf-8로 보강한다.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

console = Console()

_STEP_LABELS = {
    StepType.CLONE:         "Clone Repository",
    StepType.INSTALL:       "Install Dependencies",
    StepType.TEST:          "Run Tests",
    StepType.SECURITY_SCAN: "Security Scan",
    StepType.BUILD:         "Build Artifact",
    StepType.REPORT:        "Generate Report",
}
_TOTAL_STEPS = len(_STEP_LABELS)


def _print_header(pipeline_id: str, github_url: str) -> None:
    console.print()
    console.print(Rule(f"[bold]Pipeline  [cyan]{pipeline_id[:8]}[/][/]"))
    console.print(f"  [dim]repo:[/]  {github_url}")
    console.print()


def _print_start(step_type: StepType, index: int) -> None:
    label = _STEP_LABELS.get(step_type, step_type.value)
    console.print(f"  [bold cyan][{index}/{_TOTAL_STEPS}][/]  {label:<28} [dim]running...[/]")


def _summarize_reason(result: StepResult, limit: int = 140) -> str:
    reason = (result.error or "").strip()
    if not reason:
        reason = (result.log or "").strip()

    if not reason:
        return ""

    first_line = reason.splitlines()[0].strip()
    if len(first_line) > limit:
        return first_line[: limit - 3].rstrip() + "..."
    return first_line


def _print_done(step_type: StepType, index: int, result: StepResult) -> None:
    label = _STEP_LABELS.get(step_type, step_type.value)
    elapsed = ""
    if result.started_at and result.finished_at:
        secs = (result.finished_at - result.started_at).total_seconds()
        elapsed = f"[dim]{secs:.1f}s[/]"

    if result.status == StepStatus.SUCCESS:
        icon, stat = "[bold green]✓[/]", f"[green]done[/]  {elapsed}"
    elif result.status == StepStatus.SKIPPED:
        reason = _summarize_reason(result)
        extra = f"  [dim]{reason}[/]" if reason else ""
        icon, stat = "[bold yellow]⊘[/]", f"[yellow]skipped[/]  {elapsed}{extra}"
    else:
        reason = _summarize_reason(result)
        extra = f"  [dim]{reason}[/]" if reason else ""
        icon, stat = "[bold red]✗[/]", f"[red]failed[/]  {elapsed}{extra}"

    # 이전 running... 줄 덮어쓰기
    console.print(f"\033[1A\033[2K  {icon}  {label:<28} {stat}")


def _print_footer(status: PipelineStatus, vuln_count: int, elapsed: float = 0.0) -> None:
    console.print()
    elapsed_str = f"[dim]{elapsed:.1f}s total[/]" if elapsed > 0 else ""
    if status == PipelineStatus.SUCCESS:
        console.print(Rule(f"[bold green]Pipeline completed[/]  vulnerabilities: {vuln_count}  {elapsed_str}"))
    else:
        console.print(Rule(f"[bold red]Pipeline failed[/]  {elapsed_str}"))
    console.print()


class PipelineRunner:
    """clone → install → test → security_scan → report 순서로 실행."""

    def __init__(self) -> None:
        self._executor = StepExecutor()
        self._cve_service = CVEService()

    async def run(
        self,
        pipeline_id: str,
        github_url: str,
        db: AsyncSession,
        selected_cwe_ids: list[str] | None = None,
        selected_cve_fields: list[str] | None = None,
        changed_files: list[str] | None = None,
    ) -> None:
        pipeline = await self._fetch_pipeline(pipeline_id, db)
        if pipeline is None:
            logger.error("PipelineRunner: pipeline not found — id=%s", pipeline_id)
            return

        pipeline.status = PipelineStatus.RUNNING
        pipeline.started_at = datetime.now(tz=timezone.utc)
        pipeline.steps = []
        await db.flush()

        _cwe_ids = selected_cwe_ids or ["CWE-89"]
        # 기본값: cve_id, cwe, cvss_score, description (4개)
        _cve_fields = selected_cve_fields or ["cve_id", "cwe", "cvss_score", "description"]
        workspace_dir = tempfile.mkdtemp(prefix=f"pipeline_{pipeline_id[:8]}_")
        context: dict = {
            "github_url": github_url,
            "workspace_dir": workspace_dir,
            "pipeline_id": pipeline_id,
            "repo_path": "",
            "language": "unknown",
            "package_manager": "unknown",
            "selected_cwe_ids": _cwe_ids,
            "selected_cve_fields": _cve_fields,
            "changed_files": changed_files,
            "cve_map": {},
            "cve_list": [],
            "vulnerabilities": [],
            "step_results": [],
        }
        final_status = PipelineStatus.SUCCESS
        _start_time = time.monotonic()

        _print_header(pipeline_id, github_url)

        try:
            # ── 1. Clone ──────────────────────────────────────────────────
            clone_result = await self._run_step(StepType.CLONE, context, pipeline, db, step_index=1)
            if clone_result.status == StepStatus.FAILED:
                final_status = PipelineStatus.FAILED
                await self._finalize(pipeline, final_status, db)
                _print_footer(final_status, 0, time.monotonic() - _start_time)
                return

            context["repo_path"] = clone_result.metadata.get("repo_path", "")
            pipeline.commit_sha = clone_result.metadata.get("commit_sha") or None
            pipeline.branch = clone_result.metadata.get("branch") or None
            await db.flush()

            # ── 언어 감지 ──────────────────────────────────────────────
            clone_repo_path = context["repo_path"]
            execution_repo_path = detect_project_root(clone_repo_path)
            context["repo_root_path"] = clone_repo_path
            context["repo_path"] = execution_repo_path

            language = detect_language(execution_repo_path)
            package_manager = detect_package_manager(execution_repo_path, language)
            context["language"] = language
            context["package_manager"] = package_manager

            # ── 2. Install ────────────────────────────────────────────────
            # install 실패해도 보안 분석은 계속 진행
            install_result = await self._run_step(StepType.INSTALL, context, pipeline, db, step_index=2)
            context["install_status"] = install_result.status.value

            # ── 3. Test ───────────────────────────────────────────────────
            test_result = await self._run_step(StepType.TEST, context, pipeline, db, step_index=3)
            context["test_status"] = test_result.status.value

            # cve_service와 db를 context에 넣어 SecurityScanStep이 CWE별로 직접 조회
            context["cve_service"] = self._cve_service
            context["db"] = db

            # ── 4. Security Scan ──────────────────────────────────────────
            scan_result = await self._run_step(StepType.SECURITY_SCAN, context, pipeline, db, step_index=4)
            if scan_result.status == StepStatus.FAILED:
                final_status = PipelineStatus.FAILED
                await self._finalize(pipeline, final_status, db)
                _print_footer(final_status, 0, time.monotonic() - _start_time)
                return

            vulnerabilities: list[dict] = scan_result.metadata.get("vulnerabilities", [])
            context["vulnerabilities"] = vulnerabilities
            context["cwe_scan_times"] = scan_result.metadata.get("cwe_scan_times", {})
            await self._save_vulnerabilities(pipeline_id, vulnerabilities, db)

            # ── 5. Build ──────────────────────────────────────────────────
            build_result = await self._run_step(StepType.BUILD, context, pipeline, db, step_index=5)
            if build_result.status == StepStatus.FAILED:
                final_status = PipelineStatus.FAILED
                logger.warning(
                    "[pipeline=%s] build failed, but report step will still run",
                    pipeline_id,
                )

            # ── 6. Report ─────────────────────────────────────────────────
            context["step_results"] = [
                sr.to_dict() for sr in context.get("_step_result_objects", [])
            ]
            context["pipeline_elapsed"] = time.monotonic() - _start_time
            report_result = await self._run_step(StepType.REPORT, context, pipeline, db, step_index=6)

            # 리포트 텍스트 콘솔 출력
            report_text: str = report_result.metadata.get("report_text", "") if report_result.metadata else ""
            if report_text:
                console.print()
                for report_line in report_text.splitlines():
                    console.print(report_line)

        except Exception as exc:
            logger.exception("[pipeline=%s] unhandled exception", pipeline_id)
            final_status = PipelineStatus.FAILED
            error_entry = {
                "type": "runner_error",
                "status": StepStatus.FAILED.value,
                "error": str(exc),
                "started_at": datetime.now(tz=timezone.utc).isoformat(),
                "finished_at": datetime.now(tz=timezone.utc).isoformat(),
            }
            pipeline.steps = list(pipeline.steps or []) + [error_entry]

        finally:
            self._cleanup_workspace(workspace_dir)

        vuln_count = len(context.get("vulnerabilities", []))
        _print_footer(final_status, vuln_count, time.monotonic() - _start_time)
        await self._finalize(pipeline, final_status, db)

    # ── 내부 헬퍼 ──────────────────────────────────────────────────────────

    async def _run_step(
        self,
        step_type: StepType,
        context: dict,
        pipeline: Pipeline,
        db: AsyncSession,
        step_index: int,
    ) -> StepResult:
        _print_start(step_type, step_index)
        result = await self._executor.execute(step_type, context)
        _print_done(step_type, step_index, result)

        pipeline.steps = list(pipeline.steps or []) + [result.to_dict()]
        if "_step_result_objects" not in context:
            context["_step_result_objects"] = []
        context["_step_result_objects"].append(result)
        await db.flush()
        return result

    async def _fetch_pipeline(self, pipeline_id: str, db: AsyncSession) -> Pipeline | None:
        try:
            uid = uuid.UUID(pipeline_id)
        except ValueError:
            logger.error("Invalid pipeline_id format: %s", pipeline_id)
            return None
        result = await db.execute(select(Pipeline).where(Pipeline.id == uid))
        return result.scalar_one_or_none()

    async def _save_vulnerabilities(
        self, pipeline_id: str, vulnerabilities: list[dict], db: AsyncSession
    ) -> None:
        from app.core.constants import Severity

        pipeline_uuid = uuid.UUID(pipeline_id)
        for vuln in vulnerabilities:
            try:
                severity_enum = Severity(vuln.get("severity", Severity.INFO.value))
            except ValueError:
                severity_enum = Severity.INFO

            cve_ids = vuln.get("related_cve_ids", [])
            title = vuln.get("title", "Unknown") or "Unknown"
            rule_id = vuln.get("rule_id")
            file_path = vuln.get("file_path")
            db.add(Vulnerability(
                pipeline_id=pipeline_uuid,
                cve_id=cve_ids[0] if cve_ids else vuln.get("cve_id"),
                severity=severity_enum,
                title=title[:509] + "..." if len(title) > 512 else title,
                description=vuln.get("description"),
                file_path=file_path[:2045] + "..." if file_path and len(file_path) > 2048 else file_path,
                line_number=vuln.get("line_number"),
                rule_id=rule_id[:253] + "..." if rule_id and len(rule_id) > 256 else rule_id,
                raw_output=vuln.get("raw_output"),
            ))
        if vulnerabilities:
            await db.flush()

    async def _finalize(self, pipeline: Pipeline, status: PipelineStatus, db: AsyncSession) -> None:
        pipeline.status = status
        pipeline.finished_at = datetime.now(tz=timezone.utc)
        await db.flush()

    @staticmethod
    def _cleanup_workspace(workspace_dir: str) -> None:
        try:
            if os.path.isdir(workspace_dir):
                shutil.rmtree(workspace_dir, ignore_errors=True)
        except Exception as exc:
            logger.warning("Failed to clean up workspace %s: %s", workspace_dir, exc)
