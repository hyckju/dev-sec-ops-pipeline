"""SecurityScanStep 선택적 분석(changed_files) 필터 단위 테스트.

검증 영역:
- 경로 정규화 헬퍼 (_norm_rel / _build_changed_set / _finding_in_changed)
- selective 모드: 변경 파일에 해당하는 finding만 남는다
- selective 모드: 변경 파일과 무관한 finding은 제거된다
- full 모드(changed_files=None/빈 목록): 모든 finding 유지
- metadata.scan_mode / findings_before_filter 기록
"""

from __future__ import annotations

import os

import pytest

from app.core.constants import StepStatus
from app.services.pipeline.steps import security_scan_step as sss
from app.services.pipeline.steps.security_scan_step import (
    SecurityScanStep,
    _build_changed_set,
    _finding_in_changed,
    _norm_rel,
)


# ── 헬퍼 단위 테스트 ────────────────────────────────────────────────────


def test_norm_rel_unifies_separators_and_strips_dot_slash():
    assert _norm_rel("src\\app\\main.py") == "src/app/main.py"
    assert _norm_rel("./src/app/main.py") == "src/app/main.py"
    assert _norm_rel("  ./a/b.py  ") == "a/b.py"
    # 선행 './'만 제거 — 점으로 시작하는 hidden 파일명은 보존
    assert _norm_rel(".env") == ".env"


def test_build_changed_set_none_and_blank_to_none():
    assert _build_changed_set(None) is None
    assert _build_changed_set([]) is None
    assert _build_changed_set(["", "   "]) is None


def test_build_changed_set_normalizes_entries():
    s = _build_changed_set(["src\\a.py", "./b.py", " c.py "])
    assert s == {"src/a.py", "b.py", "c.py"}


def test_finding_in_changed_matches_relative_to_root():
    root = os.path.join("tmp", "repo")
    abs_path = os.path.join(root, "src", "app", "main.py")
    changed = {"src/app/main.py"}
    assert _finding_in_changed(abs_path, root, changed) is True


def test_finding_in_changed_rejects_unlisted_file():
    root = os.path.join("tmp", "repo")
    abs_path = os.path.join(root, "src", "app", "other.py")
    changed = {"src/app/main.py"}
    assert _finding_in_changed(abs_path, root, changed) is False


def test_finding_in_changed_empty_path_is_false():
    assert _finding_in_changed("", "/tmp/repo", {"a.py"}) is False


# ── run() 레벨 필터 테스트 ──────────────────────────────────────────────


@pytest.fixture
def _no_ai(monkeypatch):
    """AI 후처리(analyze_findings)를 no-op으로 패치해 네트워크 호출 제거."""
    async def _noop(vulns, target):
        return {}

    monkeypatch.setattr(
        "app.integrations.gemini.client.analyze_findings", _noop
    )


def _patch_semgrep(monkeypatch, findings: list[dict]) -> None:
    """SemgrepService.run_cwe_scan을 고정 findings 반환 동기 함수로 패치."""

    def _fake_run_cwe_scan(self, repo_path, cwe_ids, cwe_cve_map):
        return findings

    monkeypatch.setattr(
        "app.services.security.semgrep_service.SemgrepService.run_cwe_scan",
        _fake_run_cwe_scan,
    )


async def test_run_selective_keeps_only_changed_files(tmp_path, monkeypatch, _no_ai):
    """selective 모드: 변경 파일에 해당하는 finding만 남고 나머지는 제거된다."""
    repo_root = str(tmp_path)
    changed_file = os.path.join(repo_root, "src", "app", "main.py")
    other_file = os.path.join(repo_root, "src", "app", "other.py")

    _patch_semgrep(monkeypatch, [
        {"rule_id": "r1", "file_path": changed_file, "message": "hit", "cvss_score": 9.1},
        {"rule_id": "r2", "file_path": other_file, "message": "miss", "cvss_score": 5.0},
    ])

    result = await SecurityScanStep().run(
        repo_path=repo_root,
        language="python",
        cve_list=[],
        selected_cwe_ids=["CWE-89"],
        changed_files=["src/app/main.py"],
        repo_root_path=repo_root,
    )

    assert result.status == StepStatus.SUCCESS
    vulns = result.metadata["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["rule_id"] == "r1"
    assert result.metadata["scan_mode"] == "selective"
    assert result.metadata["findings_before_filter"] == 2


async def test_run_full_mode_keeps_all_findings(tmp_path, monkeypatch, _no_ai):
    """full 모드(changed_files=None): 모든 finding 유지, scan_mode=full."""
    repo_root = str(tmp_path)
    _patch_semgrep(monkeypatch, [
        {"rule_id": "r1", "file_path": os.path.join(repo_root, "a.py"), "message": "x", "cvss_score": 9.1},
        {"rule_id": "r2", "file_path": os.path.join(repo_root, "b.py"), "message": "y", "cvss_score": 5.0},
    ])

    result = await SecurityScanStep().run(
        repo_path=repo_root,
        language="python",
        cve_list=[],
        selected_cwe_ids=["CWE-89"],
        changed_files=None,
        repo_root_path=repo_root,
    )

    assert result.status == StepStatus.SUCCESS
    assert len(result.metadata["vulnerabilities"]) == 2
    assert result.metadata["scan_mode"] == "full"
    assert result.metadata["findings_before_filter"] == 0


async def test_run_selective_no_match_yields_zero(tmp_path, monkeypatch, _no_ai):
    """변경 파일과 일치하는 finding이 없으면 0건(=변경분에 한해 안전)."""
    repo_root = str(tmp_path)
    _patch_semgrep(monkeypatch, [
        {"rule_id": "r1", "file_path": os.path.join(repo_root, "untouched.py"), "message": "x", "cvss_score": 9.1},
    ])

    result = await SecurityScanStep().run(
        repo_path=repo_root,
        language="python",
        cve_list=[],
        selected_cwe_ids=["CWE-89"],
        changed_files=["only/this/changed.py"],
        repo_root_path=repo_root,
    )

    assert result.status == StepStatus.SUCCESS
    assert result.metadata["vulnerabilities"] == []
    assert result.metadata["scan_mode"] == "selective"
    assert result.metadata["findings_before_filter"] == 1
