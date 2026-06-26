"""6개 CWE 골든 픽스처 통합 테스트.

의도적 취약 코드 픽스처(`fixtures/cwe_golden/`)에 대해
SemgrepService.run_cwe_scan이 6개 CWE를 모두 탐지하는지 검증한다.

이 테스트의 가치:
1. 11월 기업 실증의 정탐 정확도 측정용 골든 데이터셋 시드 (로드맵 §2 11월 항목)
2. 향후 룰팩 변경/Semgrep 업그레이드로 인한 탐지 회귀 방지

전제: semgrep 바이너리가 PATH에 있어야 한다 (없으면 모듈 전체 skip).
원격 룰팩(p/sql-injection 등)을 받기 위해 네트워크가 필요할 수 있다.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.integrations.semgrep.runner import _resolve_semgrep_executable
from app.services.security.semgrep_service import CWE_SCAN_CONFIG, SemgrepService

SEMGREP_AVAILABLE = _resolve_semgrep_executable() is not None
requires_semgrep = pytest.mark.skipif(
    not SEMGREP_AVAILABLE,
    reason="semgrep binary not found — venv PATH 미등록 또는 미설치. SEMGREP_BINARY 환경변수로 경로 지정 가능",
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cwe_golden"
TARGET_CWES = ["CWE-89", "CWE-79", "CWE-22", "CWE-918", "CWE-78", "CWE-798"]


# ── fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def scan_results() -> list[dict]:
    """모든 CWE 룰팩을 골든 픽스처에 한 번에 적용 (스캔 비용 절감).

    semgrep 인증/네트워크 문제로 실행 자체가 안 되면 ERROR 대신 SKIPPED 처리.
    11월 실증을 위한 진짜 검증은 `semgrep login` 후 환경 변수
    `RUN_SEMGREP_GOLDEN=1` 으로 강제 실행할 수 있다.
    """
    svc = SemgrepService()
    try:
        return svc.run_cwe_scan(
            repo_path=str(FIXTURES_DIR),
            selected_cwe_ids=TARGET_CWES,
            cve_map={cwe: [] for cwe in TARGET_CWES},
        )
    except RuntimeError as exc:
        # 인증 안 됨 / 네트워크 불가 / 룰팩 다운로드 실패 등
        if os.environ.get("RUN_SEMGREP_GOLDEN") == "1":
            raise  # 명시적으로 강제 실행 모드면 실패 그대로 노출
        pytest.skip(
            f"semgrep 실행 실패 — login/network 확인 필요 ({exc}). "
            f"강제 실행하려면 RUN_SEMGREP_GOLDEN=1 환경 변수 설정."
        )


# ── 픽스처 구조 sanity check (skipif 대상이 아님) ─────────────────────


def test_fixture_directory_has_one_subdir_per_cwe():
    """각 CWE마다 전용 서브디렉토리가 존재해야 한다 (회귀 시 즉시 가시화)."""
    expected_subdirs = {
        "cwe_89_sql_injection",
        "cwe_79_xss",
        "cwe_22_path_traversal",
        "cwe_918_ssrf",
        "cwe_78_command_injection",
        "cwe_798_hardcoded_credentials",
    }
    actual = {p.name for p in FIXTURES_DIR.iterdir() if p.is_dir()}
    assert expected_subdirs.issubset(actual), (
        f"missing CWE fixture dirs: {expected_subdirs - actual}"
    )


# ── 6개 CWE 탐지 보장 (semgrep 필요) ──────────────────────────────────


@requires_semgrep
@pytest.mark.parametrize("cwe_id", TARGET_CWES)
def test_each_cwe_is_detected_in_golden_corpus(scan_results, cwe_id):
    """6개 CWE 각각에 대해 최소 1건 이상 탐지되어야 한다."""
    detected = [
        f for f in scan_results if (f.get("detected_cwe") or "").upper() == cwe_id
    ]
    label = CWE_SCAN_CONFIG[cwe_id]["label"]
    assert detected, (
        f"{cwe_id} ({label}) 미탐 — 픽스처/룰팩 정렬 확인 필요. "
        f"총 finding 수: {len(scan_results)}, "
        f"탐지된 CWE: {sorted({(f.get('detected_cwe') or '?') for f in scan_results})}"
    )


@requires_semgrep
def test_findings_have_minimum_required_fields(scan_results):
    """모든 finding은 PR 코멘트 작성에 필요한 file_path/line_start를 가져야 한다."""
    assert scan_results, "스캔 결과가 비어 있다 — 룰팩 다운로드/파싱 실패 가능성"
    for finding in scan_results:
        assert finding.get("file_path"), f"file_path 누락: {finding}"
        assert finding.get("line_start", 0) > 0, f"line_start 누락: {finding}"
        assert finding.get("rule_id"), f"rule_id 누락: {finding}"


@requires_semgrep
def test_findings_are_localized_to_expected_fixture_files(scan_results):
    """각 CWE finding의 file_path는 해당 CWE 서브디렉토리에 속해야 한다 (오탐 회귀 방지)."""
    cwe_to_subdir = {
        "CWE-89": "cwe_89_sql_injection",
        "CWE-79": "cwe_79_xss",
        "CWE-22": "cwe_22_path_traversal",
        "CWE-918": "cwe_918_ssrf",
        "CWE-78": "cwe_78_command_injection",
        "CWE-798": "cwe_798_hardcoded_credentials",
    }
    mismatched: list[tuple[str, str, str]] = []
    for f in scan_results:
        detected = (f.get("detected_cwe") or "").upper()
        subdir = cwe_to_subdir.get(detected)
        if subdir and subdir not in f.get("file_path", ""):
            mismatched.append((detected, subdir, f.get("file_path", "")))
    assert not mismatched, (
        f"finding이 잘못된 픽스처에서 잡혔다 (CWE, 기대 서브디렉토리, 실제 경로): {mismatched}"
    )
