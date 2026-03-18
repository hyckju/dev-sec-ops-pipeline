"""
DevSecOps 파이프라인 대화형 CLI 실행기.

사용법:
    python3 scripts/scan.py
    python3 scripts/scan.py https://github.com/owner/repo
"""

import sys
import httpx
import questionary
import time
import uuid
from questionary import Style

# ── 스타일 (Codex CLI 스타일) ──────────────────────────────────────────────
_STYLE = Style([
    ("qmark",        "fg:#00bcd4 bold"),
    ("question",     "bold"),
    ("answer",       "fg:#00bcd4 bold"),
    ("pointer",      "fg:#00bcd4 bold"),
    ("highlighted",  "fg:#00bcd4 bold"),
    ("selected",     "fg:#ffffff bg:#00bcd4"),
    ("separator",    "fg:#6c737a"),
    ("instruction",  "fg:#6c737a"),
])

# ── 보안 검사 항목 (CWE 매핑) ────────────────────────────────────────────
_SCAN_CHOICES = [
    questionary.Choice("SQL Injection          (CWE-89)",  value="CWE-89",  checked=True),
    questionary.Choice("XSS                    (CWE-79)",  value="CWE-79",  checked=True),
    questionary.Choice("Path Traversal         (CWE-22)",  value="CWE-22",  checked=False),
    questionary.Choice("SSRF                   (CWE-918)", value="CWE-918", checked=False),
    questionary.Choice("Command Injection       (CWE-78)",  value="CWE-78",  checked=False),
    questionary.Choice("하드코딩 API 키         (CWE-798)", value="CWE-798", checked=False),
]

# ── CVE 정보 표시 필드 ─────────────────────────────────────────────────
_FIELD_CHOICES = [
    questionary.Choice("CVE ID + NVD 링크",       value="cve_id",      checked=True),
    questionary.Choice("CWE 분류 + MITRE 링크",   value="cwe",         checked=True),
    questionary.Choice("CVSS 심각도 점수",         value="cvss_score",  checked=True),
    questionary.Choice("취약점 설명 (Description)", value="description", checked=True),
    questionary.Choice("CISA KEV 등재 여부",       value="kev_listed",  checked=False),
    questionary.Choice("영향받는 제품 (CPE)",      value="cpe_list",    checked=False),
]

API_BASE = "http://localhost:8000"


def _print_banner() -> None:
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   🔍  DevSecOps Security Scanner     ║")
    print("  ╚══════════════════════════════════════╝")
    print("\n  * Only security scan will be performed. Dependency, test, and build steps are skipped.")
    print("  * Recommendation: Review detected vulnerabilities and apply secure coding practices.")
    print()


def _ask_repo_url(prefill: str = "") -> str:
    url = questionary.text(
        "GitHub 저장소 URL을 입력하세요:",
        default=prefill,
        style=_STYLE,
    ).ask()
    if not url:
        print("URL이 입력되지 않았습니다. 종료합니다.")
        sys.exit(0)
    return url.strip()


def _ask_scan_types() -> list[str]:
    selected = questionary.checkbox(
        "실행할 보안 검사를 선택하세요: (Space: 선택/해제 · Enter: 확인)",
        choices=_SCAN_CHOICES,
        style=_STYLE,
    ).ask()
    if not selected:
        print("검사 항목이 선택되지 않았습니다. 종료합니다.")
        sys.exit(0)
    return selected


def _ask_cve_fields() -> list[str]:
    selected = questionary.checkbox(
        "리포트에 포함할 CVE 정보를 선택하세요: (최대 4개 · Space: 선택/해제 · Enter: 확인)",
        choices=_FIELD_CHOICES,
        style=_STYLE,
        validate=lambda ans: True if 1 <= len(ans) <= 4 else "최소 1개, 최대 4개까지 선택 가능합니다.",
    ).ask()
    if not selected:
        print("CVE 필드가 선택되지 않았습니다. 종료합니다.")
        sys.exit(0)
    return selected


def _confirm(repo_url: str, cwe_ids: list[str], cve_fields: list[str]) -> bool:
    # 선택 요약 출력
    label_map = {
        "CWE-89":  "SQL Injection",
        "CWE-79":  "XSS",
        "CWE-22":  "Path Traversal",
        "CWE-918": "SSRF",
        "CWE-78":  "Command Injection",
        "CWE-798": "하드코딩 API 키",
    }
    print()
    print(f"  저장소  : {repo_url}")
    print(f"  검사 항목: {', '.join(label_map.get(c, c) for c in cwe_ids)}")
    print(f"  CVE 필드: {', '.join(cve_fields)}")
    print()
    return questionary.confirm("파이프라인을 시작할까요?", default=True, style=_STYLE).ask()


def _print_step_progress(steps: list) -> None:
    print("\n  ── Pipeline Steps ────────────────────────────────")
    for step in steps:
        status = step.get("status", "?")
        started = step.get("started_at", "")
        finished = step.get("finished_at", "")
        log = step.get("log", "")
        print(f"    {step.get('type', '?'):10}  {status:8}  {started} → {finished}")
        if log:
            print("      ── Log ────────────────────────────────")
            for line in log.splitlines():
                print(f"      {line}")
            print("      ──────────────────────────────────────")


def _wait_and_print_pipeline(pipeline_id: str) -> None:
    print("\n  실시간 진행 상황을 출력합니다...")
    last_status = None
    printed_steps = set()
    while True:
        try:
            resp = httpx.get(f"{API_BASE}/api/v1/pipelines/{pipeline_id}", timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "?")
            steps = data.get("steps", [])
            if status != last_status:
                print(f"\n  [Pipeline Status] {status}")
                last_status = status
            for step in steps:
                step_id = f"{step.get('type', '?')}-{step.get('status', '?')}"
                if step_id not in printed_steps:
                    _print_step_progress([step])
                    printed_steps.add(step_id)
            if status in ("success", "failed", "cancelled"):
                print("\n  파이프라인이 종료되었습니다.")
                break
        except Exception as e:
            print(f"  [오류] 진행 상황 조회 실패: {e}")
            break
        time.sleep(2)


def _run_pipeline(repo_url: str, cwe_ids: list[str], cve_fields: list[str]) -> None:
    print()
    print("  파이프라인을 시작합니다...")
    print()
    try:
        resp = httpx.post(
            f"{API_BASE}/api/v1/pipelines/",
            json={
                "github_url": repo_url,
                "selected_cwe_ids": cwe_ids,
                "selected_cve_fields": cve_fields,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
        pipeline_id = data.get("id", "?")
        status = data.get("status", "?")
        print(f"  ✅ 파이프라인 생성됨")
        print(f"     Pipeline ID : {pipeline_id}")
        print(f"     Status      : {status}")
        print()
        print(f"  📊 결과 확인: GET {API_BASE}/api/v1/pipelines/{pipeline_id}")
        _wait_and_print_pipeline(pipeline_id)
    except httpx.ConnectError:
        print(f"  ❌ 서버에 연결할 수 없습니다. FastAPI 서버가 실행 중인지 확인하세요.")
        print(f"     uvicorn app.main:app --reload")
        print()
    except httpx.HTTPStatusError as e:
        print(f"  ❌ API 오류: {e.response.status_code} — {e.response.text[:200]}")
        print()
    except Exception as e:
        print(f"  ❌ 오류 발생: {e}")
        print()


def main() -> None:
    _print_banner()

    # CLI 인자로 URL 전달 가능
    prefill_url = sys.argv[1] if len(sys.argv) > 1 else ""

    repo_url   = _ask_repo_url(prefill_url)
    cwe_ids    = _ask_scan_types()
    cve_fields = _ask_cve_fields()

    if not _confirm(repo_url, cwe_ids, cve_fields):
        print("  취소되었습니다.")
        sys.exit(0)

    _run_pipeline(repo_url, cwe_ids, cve_fields)


if __name__ == "__main__":
    main()
