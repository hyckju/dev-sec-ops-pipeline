"""
Anthropic Claude API 클라이언트 (AI 보안 제안 생성).
"""

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_MODEL = "claude-haiku-4-5-20251001"  # 빠르고 비용 효율적
_TIMEOUT = 60.0


def _is_available() -> bool:
    return bool(settings.ANTHROPIC_API_KEY)


async def _call_claude(prompt: str) -> str:
    """Anthropic Claude Messages API를 호출하고 텍스트 응답을 반환한다."""
    if not _is_available():
        raise RuntimeError("ANTHROPIC_API_KEY 가 설정되지 않았습니다.")

    payload = {
        "model": _MODEL,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": settings.ANTHROPIC_API_KEY,
        "anthropic-version": _ANTHROPIC_VERSION,
        "content-type": "application/json",
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(_ANTHROPIC_API_URL, headers=headers, json=payload)
        resp.raise_for_status()

    data = resp.json()
    try:
        return data["content"][0]["text"].strip()
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Claude 응답 파싱 실패: {data}") from exc


import os as _os
import re as _re

# 분석 결과 타입: {0-based 인덱스: "suggestion" str}
AnalysisResult = dict[int, dict]

# Semgrep이 code_snippet 대신 돌려주는 무의미한 플레이스홀더들
_INVALID_SNIPPETS = {"requires login", "requires login to view", ""}


def _read_snippet_from_file(file_path: str, line_number: int | None, context: int = 3) -> str:
    """파일에서 직접 해당 줄 ±context 줄을 읽어 반환한다."""
    if not file_path or not line_number:
        return ""
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "".join(lines[start:end]).strip()
    except Exception:
        return ""


def _parse_analysis(text: str) -> AnalysisResult:
    """
    AI 응답에서 [ANALYSIS] 섹션을 파싱한다.

    응답 형식:
        [ANALYSIS]
        1|수정 방법
        2|수정 방법
    """
    result: AnalysisResult = {}
    section = _re.search(r'\[ANALYSIS\](.*?)$', text, _re.DOTALL)
    if not section:
        return result
    for line in section.group(1).strip().splitlines():
        line = line.strip()
        m = _re.match(r'(\d+)\|(.+)', line)
        if m:
            idx = int(m.group(1)) - 1  # 0-based
            result[idx] = {"suggestion": m.group(2).strip()}
    return result


async def analyze_findings(vulnerabilities: list[dict], repo_url: str) -> AnalysisResult:
    """
    Semgrep + AI 탐지 결과 전체에 대해 코드 기반 수정 제안을 생성한다.

    Returns:
        {0-based 인덱스: {"suggestion": str}} dict.
        오류 시 빈 dict 반환 (non-fatal).
    """
    if not _is_available() or not vulnerabilities:
        return {}

    vuln_blocks: list[str] = []
    for i, v in enumerate(vulnerabilities[:20], 1):
        raw_snippet = (v.get("code_snippet") or "").strip()
        if raw_snippet.lower() in _INVALID_SNIPPETS:
            raw_snippet = _read_snippet_from_file(
                v.get("file_path", ""),
                v.get("line_number") or v.get("line_start"),
            )
        snippet_section = f"\n코드:\n```\n{raw_snippet[:400]}\n```" if raw_snippet else ""
        source_tag = f" [{v.get('source', 'semgrep').upper()}]" if v.get("source") else ""
        vuln_blocks.append(
            f"[{i}]{source_tag} [{v.get('severity', '?').upper()}] {v.get('rule_id', v.get('title', '?'))[:80]}\n"
            f"    파일: {_os.path.basename(v.get('file_path', '?'))}:{v.get('line_number') or v.get('line_start', '?')}"
            f" | CWE: {v.get('cwe', 'N/A')}"
            f"{snippet_section}"
        )

    total = len(vulnerabilities)
    vulns_block = "\n\n".join(vuln_blocks)

    # 아래는 프롬프트 예시(한글) - 실제 프롬프트에는 포함되지 않음
    # 각 항목에 대해 코드 맥락에 맞는 구체적인 수정 방법을 영어 1~2문장으로 작성하세요.
    # 저장소: {repo_url}
    # 총 탐지 항목: {total}개 (상위 {min(total, 20)}개)
    # {'=' * 50}
    # {vulns_block}
    # {'=' * 50}
    # 아래 형식으로만 응답하세요 (다른 텍스트 없이):
    # [ANALYSIS]
    # 1|수정 방법
    # 2|수정 방법
    # (모든 항목 번호에 대해 작성)

    prompt = f"""You are a senior security engineer. Here is a list of vulnerabilities detected by static analysis (Semgrep) and AI.
For each item, write a concrete remediation in English (1-2 sentences) suitable for the code context.

Repository: {repo_url}
Total findings: {total} (top {min(total, 20)})

{'=' * 50}
{vulns_block}
{'=' * 50}

Respond ONLY in the following format (no extra text):

[ANALYSIS]
1|Remediation
2|Remediation
(Write for every item number)
"""

    try:
        raw = await _call_claude(prompt)
        result = _parse_analysis(raw)
        logger.info(
            "Claude analyze_findings complete: %d suggestions for %d findings",
            len(result), total,
        )
        return result
    except Exception as exc:
        logger.debug("Claude analyze_findings failed (non-fatal): %s", exc)
        return {}


# ── AI 독립 탐지 (B안) ──────────────────────────────────────────────────────

AiFinding = dict  # {file_path, line_number, severity, title, suggestion, cwe, source}


def _parse_ai_findings(text: str, file_map: dict[str, str]) -> list[AiFinding]:
    """
        AI 독립 스캔 응답에서 [FINDINGS] 섹션을 파싱한다.

    응답 형식:
        [FINDINGS]
        1|파일명.java|42|HIGH|취약점 설명|수정 방법
    """
    findings: list[AiFinding] = []
    section = _re.search(r'\[FINDINGS\](.*?)$', text, _re.DOTALL)
    if not section:
        return findings
    for line in section.group(1).strip().splitlines():
        line = line.strip()
        if not line or line.upper().startswith("NONE"):
            continue
        m = _re.match(r'\d+\|([^|]+)\|(\d+)\|(HIGH|MEDIUM|LOW)\|([^|]+)\|(.+)', line)
        if m:
            fname = m.group(1).strip()
            lineno = int(m.group(2))
            severity = m.group(3).lower()
            desc = m.group(4).strip()
            suggestion = m.group(5).strip()
            # 절대 경로로 복원
            abs_path = next(
                (p for p in file_map if p.endswith(fname) or _os.path.basename(p) == fname),
                fname,
            )
            findings.append({
                "file_path": abs_path,
                "line_number": lineno,
                "severity": severity,
                "title": desc,
                "suggestion": suggestion,
                "source": "ai",
            })
    return findings


async def scan_files_for_cwe(
    files_content: dict[str, str],
    cwe_id: str,
    cwe_label: str,
) -> list[AiFinding]:
    """
    소스 파일들을 직접 읽어 CWE 취약점을 독립적으로 탐지한다 (B안).
    Semgrep과 무관하게 실행되므로 Semgrep이 놓친 취약점도 발견할 수 있다.

    Returns:
        발견된 취약점 목록. 오류 시 빈 리스트 반환 (non-fatal).
    """
    if not _is_available() or not files_content:
        return []

    file_blocks: list[str] = []
    for path, content in files_content.items():
        fname = _os.path.basename(path)
        # 파일당 최대 3000자
        file_blocks.append(f"=== {fname} ===\n{content[:3000]}")

    files_text = "\n\n".join(file_blocks)

    prompt = f"""당신은 시니어 보안 연구원입니다. 아래 소스 파일들에서 {cwe_id} ({cwe_label}) 취약점을 탐지하세요.
분석 대상 파일:

{files_text}

{'=' * 50}

실제로 존재하는 취약점만 보고하세요. 확실하지 않으면 보고하지 마세요.

취약점이 있을 경우:
[FINDINGS]
1|파일명.java|42|HIGH|취약점 설명|수정 방법
2|파일명.java|78|MEDIUM|취약점 설명|수정 방법

취약점이 없을 경우:
[FINDINGS]
NONE
"""

    try:
        raw = await _call_claude(prompt)
        result = _parse_ai_findings(raw, files_content)
        logger.info("Claude scan_files_for_cwe: %d findings for %s", len(result), cwe_id)
        return result
    except Exception as exc:
        logger.debug("Claude scan_files_for_cwe failed (non-fatal): %s", exc)
        return []
