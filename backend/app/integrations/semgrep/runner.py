import json
import logging
import os
import shutil
import subprocess
import tempfile

from app.core.config import settings

logger = logging.getLogger(__name__)

SQL_INJECTION_RULES = [
    "p/sql-injection",
    "p/owasp-top-ten",
]

# 설치 산출물/캐시/문서/테스트 경로를 제외해 스캔 속도를 최적화한다.
_DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    "node_modules",
    "coverage",
    ".coverage",
    ".nyc_output",
    ".next",
    ".nuxt",
    ".cache",
    "dist",
    "out",
    "build",
    "target",
    "tmp",
    "temp",
    "venv",
    ".venv",
    "env",
    "site-packages",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    # 축소된 JS/CSS 라이브러리 (대용량, 보안 수정 대상 아님)
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.chunk.js",
    # 컴파일 산출물
    "*.class",
    "*.jar",
    "*.war",
    "*.pyc",
    # 문서/테스트 데이터
    "docs",
    "documentation",
    "*.md",
    "*.txt",
    "*.csv",
    "*.log",
)

_EMPTY_RESULT: dict = {"results": [], "errors": [], "stats": {}}

# 10코어 기준 최대 병렬도 활용
_PER_FILE_TIMEOUT_SEC = 30
_TIMEOUT_THRESHOLD = 5
_JOBS = 8
# 500KB 초과 파일(minified JS 등) 스킵 — 소스 파일치고 너무 큰 경우 스캔 가치 낮음
_MAX_TARGET_BYTES = 300_000


def _resolve_semgrep_executable() -> str | None:
    """환경에 맞는 semgrep 실행 파일 경로를 결정한다."""
    configured = (settings.SEMGREP_BINARY or "semgrep").strip()
    if not configured:
        configured = "semgrep"

    # 설정값이 절대/상대 경로라면 파일 존재 여부를 우선 확인한다.
    if os.path.sep in configured:
        return configured if os.path.isfile(configured) else None

    found = shutil.which(configured)
    if found:
        return found

    # macOS Homebrew 기본 경로 폴백
    for candidate in ("/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"):
        if os.path.isfile(candidate):
            return candidate

    return None


def _error_result(error_type: str, message: str) -> dict:
    """semgrep 실행 실패를 상위 레이어가 판단할 수 있도록 구조화된 결과를 반환한다."""
    return {
        "results": [],
        "errors": [{"type": error_type, "message": message}],
        "stats": {},
    }


class SemgrepRunner:
    """semgrep CLI를 subprocess로 실행하는 클래스."""

    def run(self, repo_path: str, rules: list[str] | None = None) -> dict:
        """
        semgrep을 subprocess로 실행하고 JSON 출력을 파싱하여 반환한다.

        Args:
            repo_path: 스캔 대상 로컬 저장소 경로
            rules: 적용할 semgrep 룰 목록. None이면 --config auto 사용.
                   예: ["p/sql-injection", "p/owasp-top-ten"]

        Returns:
            파싱된 semgrep 출력:
            {
                "results": [...],
                "errors":  [...],
                "stats":   {...},
            }
        """
        semgrep_executable = _resolve_semgrep_executable()
        if semgrep_executable is None:
            msg = (
                "semgrep executable not found. "
                f"Set SEMGREP_BINARY in .env (current={settings.SEMGREP_BINARY!r})"
            )
            logger.error(msg)
            return _error_result("execution_error", msg)

        cmd = [
            semgrep_executable,
            "--json",
            "--jobs", str(_JOBS),
            "--timeout", str(_PER_FILE_TIMEOUT_SEC),
            "--timeout-threshold", str(_TIMEOUT_THRESHOLD),
            "--max-target-bytes", str(_MAX_TARGET_BYTES),
            "--no-git-ignore",
        ]

        # 스캔 대상 범위를 고정해 파이프라인 실행마다 결과 변동을 줄인다.
        for pattern in _DEFAULT_EXCLUDES:
            cmd.extend(["--exclude", pattern])

        cmd.append(repo_path)

        if rules:
            for rule in rules:
                cmd.extend(["--config", rule])
        else:
            cmd.extend(["--config", "auto"])

        timeout = settings.SEMGREP_TIMEOUT
        logger.info(
            "Running semgrep: %s (timeout=%ds)", " ".join(cmd), timeout
        )

        try:
            with tempfile.TemporaryDirectory(prefix="semgrep_tmp_") as tmpdir:
                env = os.environ.copy()
                env["TMPDIR"] = tmpdir
                env["TMP"] = tmpdir
                env["TEMP"] = tmpdir

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    env=env,
                )

            logger.info(
                "semgrep exited with code %d for path: %s", proc.returncode, repo_path
            )

            if proc.stderr:
                # returncode 1 = findings found (정상), 2+ = 오류
                lvl = logging.WARNING if proc.returncode >= 2 else logging.DEBUG
                logger.log(lvl, "semgrep stderr: %s", proc.stderr[:2000])

            raw_text = (proc.stdout or "").strip()
            if not raw_text:
                msg = f"semgrep produced no stdout output for path: {repo_path}"
                logger.warning(msg)
                return _error_result("scan_error", msg)

            parsed: dict = json.loads(raw_text)

            errors = parsed.get("errors", [])
            if errors:
                # 파일별 파싱 실패(Syntax/Lexical error)는 정상 범위 — DEBUG 로그
                # 룰 다운로드/설정 오류 등은 실제 문제 — WARNING 로그
                parse_errors = [
                    e for e in errors
                    if "syntax" in str(e.get("type", "")).lower()
                    or "lexical" in str(e.get("type", "")).lower()
                    or "syntax error" in str(e.get("message", "")).lower()
                ]
                config_errors = [e for e in errors if e not in parse_errors]

                if config_errors:
                    logger.warning(
                        "semgrep config/rule error(s) (%d): %s",
                        len(config_errors),
                        [str(e.get("message", "?"))[:200] for e in config_errors[:5]],
                    )
                if parse_errors:
                    logger.debug(
                        "semgrep skipped %d file(s) due to parse errors "
                        "(non-code files like Dockerfile, HTML, etc.)",
                        len(parse_errors),
                    )

            results = parsed.get("results", [])
            scanned = ((parsed.get("paths") or {}).get("scanned") or [])
            if not scanned:
                msg = (
                    "semgrep scanned 0 files (paths.scanned is empty). "
                    "This indicates target-resolution failure, not a real clean result."
                )
                logger.error(msg)
                return _error_result("scan_error", msg)

            logger.info(
                "semgrep raw results: %d finding(s) for path: %s",
                len(results), repo_path,
            )

            return {
                "results": results,
                "errors": errors,
                "stats": parsed.get("stats", {}),
            }

        except subprocess.TimeoutExpired:
            msg = f"semgrep timed out after {timeout} seconds for path: {repo_path}"
            logger.warning(msg)
            return _error_result("timeout_error", msg)
        except FileNotFoundError:
            msg = "semgrep binary not found. Is it installed?"
            logger.error(msg)
            return _error_result("execution_error", msg)
        except json.JSONDecodeError as exc:
            msg = f"Failed to parse semgrep JSON output: {exc}"
            logger.error(msg)
            return _error_result("parse_error", msg)
        except Exception as exc:
            msg = f"Unexpected error while running semgrep: {exc}"
            logger.error(msg)
            return _error_result("execution_error", msg)
