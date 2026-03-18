"""언어 및 패키지 매니저 자동 감지 모듈."""

import logging
import os
from collections import Counter

logger = logging.getLogger(__name__)

# 확장자 → 언어 매핑
_EXT_LANGUAGE_MAP: dict[str, str] = {
    # Python
    ".py": "python",
    # JavaScript / TypeScript
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".tsx": "node",
    ".jsx": "node",
    # Java / Kotlin / Scala
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "java",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # PHP
    ".php": "php",
    # Ruby
    ".rb": "ruby",
    # C / C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    # C#
    ".cs": "csharp",
    # Swift
    ".swift": "swift",
    # Dart
    ".dart": "dart",
    # Elixir
    ".ex": "elixir",
    ".exs": "elixir",
    # Haskell
    ".hs": "haskell",
    ".lhs": "haskell",
}

# 설정 파일 → 언어 매핑 (우선순위 순서: 앞쪽이 더 강한 신호)
_CONFIG_FILE_MAP: list[tuple[str, str]] = [
    ("composer.json", "php"),
    ("package.json", "node"),
    ("requirements.txt", "python"),
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("setup.cfg", "python"),
    ("Pipfile", "python"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "kotlin"),
    ("go.mod", "go"),
    ("Cargo.toml", "rust"),
    ("Gemfile", "ruby"),
    ("pubspec.yaml", "dart"),
    ("pubspec.yml", "dart"),
    ("mix.exs", "elixir"),
    ("stack.yaml", "haskell"),
    ("cabal.project", "haskell"),
    ("Package.swift", "swift"),
]

# 무시할 디렉터리 목록
_IGNORED_DIRS = {
    "node_modules",
    "__pycache__",
    "vendor",
    "target",
    ".git",
    ".tox",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
}

_PROJECT_MARKERS: dict[str, int] = {
    "pyproject.toml": 5,
    "requirements.txt": 4,
    "setup.py": 4,
    "setup.cfg": 3,
    "Pipfile": 4,
    "Pipfile.lock": 3,
    "poetry.lock": 4,
    "uv.lock": 4,
    "pdm.lock": 4,
    "package.json": 5,
    "pom.xml": 5,
    "build.gradle": 5,
    "build.gradle.kts": 5,
    "build.sbt": 5,
    "go.mod": 5,
    "Cargo.toml": 5,
    "composer.json": 5,
    "Gemfile": 5,
    "CMakeLists.txt": 5,
    "Makefile": 4,
    "makefile": 4,
    "Package.swift": 5,
    "pubspec.yaml": 5,
    "pubspec.yml": 5,
    "mix.exs": 5,
    "stack.yaml": 5,
    "cabal.project": 5,
}


def _walk_repo_dirs(repo_path: str):
    for root, dirs, _files in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs if not d.startswith(".") and d not in _IGNORED_DIRS
        ]
        yield root


def detect_project_root(repo_path: str) -> str:
    """레포 전체를 재귀 탐색해 실제 실행 기준이 될 프로젝트 루트를 선택한다."""
    if not os.path.isdir(repo_path):
        return repo_path

    best_dir = repo_path
    best_score = -1
    best_depth = 10**9

    for candidate in _walk_repo_dirs(repo_path):
        try:
            names = set(os.listdir(candidate))
        except OSError:
            continue

        matched_markers = [name for name in names if name in _PROJECT_MARKERS]
        if not matched_markers:
            continue

        score = sum(_PROJECT_MARKERS[name] for name in matched_markers)

        if "tests" in names:
            score += 2
        if "src" in names:
            score += 1
        if "app" in names:
            score += 1

        rel = os.path.relpath(candidate, repo_path)
        depth = 0 if rel == "." else rel.count(os.sep) + 1

        if score > best_score or (score == best_score and depth < best_depth):
            best_dir = candidate
            best_score = score
            best_depth = depth

    logger.info(
        "Project root selected: %s (base=%s score=%d depth=%d)",
        best_dir,
        repo_path,
        best_score,
        0 if best_depth == 10**9 else best_depth,
    )
    return best_dir


def detect_language(repo_path: str) -> str:
    """
    저장소 경로를 분석하여 주 프로그래밍 언어를 감지한다.

    설정 파일(package.json, requirements.txt, pom.xml, go.mod, Cargo.toml 등)을
    먼저 확인하고, 없으면 소스 파일 확장자 분포로 판단한다.

    Args:
        repo_path: 로컬에 클론된 저장소의 절대 경로.

    Returns:
        "python" | "node" | "java" | "go" | "rust" | "unknown"
    """
    if not os.path.isdir(repo_path):
        logger.warning(
            "repo_path does not exist or is not a directory: %s", repo_path
        )
        return "unknown"

    # 1단계: 루트의 설정 파일로 언어 판단 (가장 신뢰도 높음)
    for config_file, language in _CONFIG_FILE_MAP:
        config_path = os.path.join(repo_path, config_file)
        if os.path.isfile(config_path):
            logger.info(
                "Language detected via config file '%s': %s", config_file, language
            )
            return language

    # 2단계: 확장자 빈도 분석
    ext_counter: Counter[str] = Counter()
    for root, dirs, files in os.walk(repo_path):
        # 숨김 폴더 및 불필요 디렉터리 제외
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".") and d not in _IGNORED_DIRS
        ]
        for filename in files:
            _, ext = os.path.splitext(filename)
            ext_lower = ext.lower()
            if ext_lower in _EXT_LANGUAGE_MAP:
                ext_counter[ext_lower] += 1

    if not ext_counter:
        logger.info("No recognizable source files found in: %s", repo_path)
        return "unknown"

    # 확장자 빈도 → 언어 빈도로 집계
    lang_counter: Counter[str] = Counter()
    for ext, count in ext_counter.items():
        lang = _EXT_LANGUAGE_MAP[ext]
        lang_counter[lang] += count

    detected, freq = lang_counter.most_common(1)[0]
    logger.info(
        "Language detected via extension analysis: %s (count=%d)", detected, freq
    )
    return detected


def detect_package_manager(repo_path: str, language: str) -> str:
    """
    저장소 경로와 언어 정보를 바탕으로 패키지 매니저를 감지한다.

    Args:
        repo_path: 로컬에 클론된 저장소의 절대 경로.
        language: detect_language()가 반환한 언어 문자열.

    Returns:
        패키지 매니저 이름 문자열.
        - python: "poetry" | "pipenv" | "pip"
        - node:   "yarn"   | "pnpm"   | "npm"
        - java:   "gradle" | "maven"
        - go:     "go"
        - rust:   "cargo"
        - 그 외:  "unknown"
    """

    def _exists(*filenames: str) -> bool:
        return any(
            os.path.isfile(os.path.join(repo_path, f)) for f in filenames
        )

    def _read_pyproject_text() -> str:
        pyproject_path = os.path.join(repo_path, "pyproject.toml")
        if not os.path.isfile(pyproject_path):
            return ""
        try:
            with open(pyproject_path, encoding="utf-8") as fh:
                return fh.read().lower()
        except OSError:
            return ""

    if language == "python":
        if _exists("uv.lock"):
            return "uv"
        if _exists("poetry.lock"):
            return "poetry"
        if _exists("Pipfile", "Pipfile.lock"):
            return "pipenv"
        if _exists("pdm.lock"):
            return "pdm"

        pyproject_text = _read_pyproject_text()
        if "[tool.poetry]" in pyproject_text:
            return "poetry"
        if "[tool.uv]" in pyproject_text:
            return "uv"
        if "[tool.pdm]" in pyproject_text:
            return "pdm"

        return "pip"

    if language == "node":
        if _exists("yarn.lock"):
            return "yarn"
        if _exists("pnpm-lock.yaml"):
            return "pnpm"
        return "npm"

    if language == "java":
        if _exists("gradlew", "build.gradle", "build.gradle.kts"):
            return "gradle"
        if _exists("pom.xml"):
            return "maven"
        return "maven"

    if language == "go":
        return "go"

    if language == "rust":
        return "cargo"

    if language == "php":
        if _exists("composer.json"):
            return "composer"
        return "unknown"

    if language == "ruby":
        if _exists("Gemfile"):
            return "bundler"
        return "unknown"

    if language == "kotlin":
        if _exists("gradlew", "build.gradle.kts"):
            return "gradle"
        if _exists("pom.xml"):
            return "maven"
        return "gradle"

    if language == "scala":
        if _exists("build.sbt"):
            return "sbt"
        if _exists("pom.xml"):
            return "maven"
        return "sbt"

    if language in ("c", "cpp"):
        if _exists("CMakeLists.txt"):
            return "cmake"
        if _exists("Makefile", "makefile"):
            return "make"
        return "unknown"

    if language == "csharp":
        return "dotnet"

    if language == "swift":
        return "swift"

    if language == "dart":
        return "pub"

    if language == "elixir":
        return "mix"

    if language == "haskell":
        if _exists("stack.yaml"):
            return "stack"
        return "cabal"

    logger.info(
        "Cannot determine package manager for language '%s'; returning 'unknown'",
        language,
    )
    return "unknown"
