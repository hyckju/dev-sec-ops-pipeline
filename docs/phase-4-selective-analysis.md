# Phase 4 — 선택적 분석 강화 (구현 설계·완료 보고)

작성: 2026-06-10
관련 문서: [`phase-3-github-actions.md`](./phase-3-github-actions.md), [`progress-and-roadmap.md`](./progress-and-roadmap.md)
상태: **코드 작업 완료** — `changed_files`(PR diff) 사후 필터 + `scan_mode`(selective/full) 비교 로깅, `vars.SECSCAN_SELECTIVE` 게이트, 단위 테스트 11건(전체 **112 passed + 8 skipped**). 잔여는 라이브 selective 실측(11월 §4.4 데이터 수집).

---

## 목적

신청서의 **"선택적 분석"** 차별점을 실제 구현으로 채운다. PR에서 **변경된 파일만** 스캔해
대형 저장소에서 스캔 시간을 줄이고, PR 단위로 "이번 변경분이 안전한가"를 빠르게 회신한다.

핵심 설계 판단 두 가지:
1. **사후 필터(post-filter)** — semgrep을 변경 파일에만 돌리도록 호출을 쪼개지 않고, 전체 스캔 결과(finding)를
   변경 파일 집합으로 **걸러낸다**. semgrep 룰팩은 저장소 전체 컨텍스트(import 등)를 봐야 정확하고,
   CWE별 룰 호출 구조(Phase 1)를 건드리지 않아 회귀 위험이 낮다. 시간 이득은 11월 실측으로 검증(§4.4).
2. **하위호환 우선** — `changed_files`가 없으면 **기존 전수 스캔 그대로**(`scan_mode=full`). 신규 필드는 순수 가산.

---

## 데이터 흐름

```
GitHub Action (secscan.yml)
  └─ git diff --name-only origin/<base>...HEAD      # repo 루트 기준 상대경로
       └─ POST /api/v1/pipelines/  { github_url, changed_files: [...] }
            └─ PipelineCreate (validator: 공백 항목 제거 → 모두 비면 None)
                 └─ PipelineService.create_and_run(..., changed_files)
                      └─ PipelineRunner.run(..., changed_files)   → context["changed_files"]
                           └─ StepExecutor dispatch(SECURITY_SCAN)
                                └─ SecurityScanStep.run(changed_files, repo_root_path=context["repo_root_path"])
                                     └─ semgrep finding.file_path(절대경로)를
                                        repo_root 상대경로로 환원 → changed_set 매칭 → 미일치 제거
```

`repo_root_path`는 clone 직후 runner가 context에 채운다(`detect_project_root` 적용 전의 클론 루트).
semgrep은 `repo_path`(절대경로)를 인자로 받으므로 finding의 `file_path`도 **절대경로** → 매칭 전 상대경로로 환원해야 한다.

---

## 4.1 `changed_files` 필드 + 배선

**스키마** (`backend/app/schemas/pipeline.py`)

```python
changed_files: list[str] | None = Field(
    default=None,
    description="선택적 분석 — 스캔을 이 파일 목록(저장소 루트 기준 상대경로)으로 한정한다. "
                "GitHub Action이 `git diff --name-only`로 PR 변경분을 전달한다. "
                "None 또는 빈 목록이면 전수(full) 스캔.",
)

@field_validator("changed_files")
@classmethod
def _normalize_changed_files(cls, v):
    if v is None:
        return None
    cleaned = [f.strip() for f in v if f and f.strip()]
    return cleaned or None        # 공백만 있으면 None(=전수)으로 환원
```

**배선** — 신규 필드를 호출 체인 끝(보안 스캔 스텝)까지 전달:

| 파일 | 변경 |
|---|---|
| `app/api/v1/pipelines.py` | `create_and_run(..., changed_files=body.changed_files)` |
| `app/services/pipeline/pipeline_service.py` | `create_and_run` 시그니처에 `changed_files` 추가 → `runner.run(..., changed_files)` |
| `app/services/pipeline/pipeline_runner.py` | `run` 시그니처에 추가 → `context["changed_files"] = changed_files` |
| `app/services/pipeline/step_executor.py` | SECURITY_SCAN dispatch에 `changed_files` + `repo_root_path` 전달 |

---

## 4.2 `SecurityScanStep` 사후 필터

**위치**: `backend/app/services/pipeline/steps/security_scan_step.py`

경로 정규화 헬퍼 3종(모듈 레벨, 순수 함수라 단위 테스트 용이):

```python
def _norm_rel(path):           # 구분자 '/' 통일 + 선행 './' 제거 (.env 같은 hidden은 보존)
def _build_changed_set(files): # 목록→정규화 집합. None/빈/공백뿐이면 None(=전수)
def _finding_in_changed(file_path, repo_root_path, changed_set):
    # 절대경로 → os.path.relpath(repo_root) → _norm_rel → 집합 멤버십
    # 다른 드라이브 등 relpath 불가 시 원본 경로로 폴백(ValueError 캐치)
```

필터 시점 — **semgrep 스캔 직후, finding 정규화·AI 후처리 전**:

```python
# 2. Semgrep 스캔 → cwe_findings
# 2.5 선택적 분석 — 변경 파일에 해당하는 finding만 남긴다
if _changed_set is not None:
    _findings_before_filter += len(cwe_findings)
    cwe_findings = [
        f for f in cwe_findings
        if _finding_in_changed(f.get("file_path", ""), _filter_root, _changed_set)
    ]
# 3. 정규화  4. Claude AI 후처리   ← 걸러진 finding엔 AI 호출도 안 함(비용 절감)
```

- `_filter_root = repo_root_path or repo_path` — runner가 넘긴 클론 루트 우선, 없으면 스캔 경로 폴백.
- 매칭 0개여도 정상(SUCCESS) — "변경분에 한해 취약점 없음" 신호로 0건 회신.

---

## 4.3 `secscan.yml` — Action이 diff 전달

**위치**: `docs/templates/secscan.yml` (스캔 대상 리포에 복사하는 템플릿)
**게이트**: 대상 리포 Variables에 `SECSCAN_SELECTIVE=true` 설정 시에만 selective. 미설정 = 전수(기본).
(`SECSCAN_ENFORCE`(§3.3)와 동일한 "파일 수정 없이 리포 설정만으로 on/off" 패턴.)

```yaml
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Compute changed files (SECSCAN_SELECTIVE=true & PR 일 때만)
        id: diff
        run: |
          set -euo pipefail
          json='[]'
          if [ "${{ vars.SECSCAN_SELECTIVE }}" = "true" ] && [ "${{ github.event_name }}" = "pull_request" ]; then
            git fetch --no-tags --depth=1 origin "${{ github.base_ref }}" 2>/dev/null || true
            files=$(git diff --name-only "origin/${{ github.base_ref }}...HEAD" 2>/dev/null || true)
            json=$(printf '%s' "$files" | jq -R -s -c 'split("\n") | map(select(length>0))')
          fi
          echo "changed_json=$json" >> "$GITHUB_OUTPUT"

      - name: Trigger pipeline
        id: trigger
        run: |
          set -euo pipefail
          repo_url="${{ github.server_url }}/${{ github.repository }}"
          # changed_files는 비어 있지 않을 때만 포함(빈 배열이면 전수). jq로 안전 직렬화.
          body=$(jq -n \
            --arg url "$repo_url" \
            --argjson files '${{ steps.diff.outputs.changed_json }}' \
            '{github_url: $url} + (if ($files | length) > 0 then {changed_files: $files} else {} end)')
          resp=$(curl -fsS -X POST "$API/api/v1/pipelines/" \
            -H "Content-Type: application/json" -H "X-API-Key: $KEY" -d "$body")
          ...
```

**구현 메모**
- `jq`로 본문을 구성해 파일명에 특수문자가 있어도 안전하게 JSON 직렬화(이전엔 문자열 보간).
- 빈 배열이면 `changed_files` 키를 **아예 생략** → 백엔드는 전수 스캔(하위호환).
- `git diff` 3-dot(`base...HEAD`)으로 PR 변경분만. `fetch-depth: 0` + base fetch로 비교 기준 확보.
- `git`/`jq`/`curl`은 ubuntu-latest 러너 기본 설치.

---

## 4.4 선택적 vs 전수 비교 로깅 (11월 실증용)

`SecurityScanStep`이 결과 metadata와 로그에 비교 지표를 남긴다:

```python
metadata = {
    "vulnerabilities": [...],
    "scan_mode": "selective" | "full",
    "findings_before_filter": int,   # selective일 때 필터 전 finding 수
    "cwe_scan_times": {...},          # CWE별 소요(기존)
}
# logger.info: "... (cwe=[...], mode=selective files=N findings=kept/total, elapsed=X.XXs)"
```

11월 실증에서 **같은 PR을 selective/full 두 번** 돌려 `elapsed`·`findings_before_filter` 대비
탐지수를 비교 → 보고서의 "선택적 분석 효과" 근거 데이터로 사용.

---

## 테스트

| 파일 | 추가 | 검증 |
|---|---|---|
| `tests/unit/services/test_security_scan_step_selective.py` (신규) | 9 | 헬퍼 6(`_norm_rel` 구분자/`./`/hidden, `_build_changed_set` None·정규화, `_finding_in_changed` 매칭/거부/빈경로) + run-level 3(selective 일치만 잔류 / full 전체 유지 / 무매칭 0건 — semgrep·AI 모킹) |
| `tests/integration/pipeline/test_pipelines_api.py` | 2 | `changed_files` 서비스 전달 / 공백뿐이면 None 환원 |
| 기존 stub 3곳(`test_pipelines_api.py`×2, `test_action_contract.py`×1) | — | `create_and_run` stub 시그니처에 `changed_files=None` 추가 |

전체: **112 passed + 8 skipped** (이전 101 → +11). `secscan.yml` YAML 파싱 검증 통과.

---

## 구현 순서 (체크리스트)

1. [x] `PipelineCreate.changed_files` 필드 + validator (4.1)
2. [x] POST → service → runner → step_executor 배선 (4.1)
3. [x] `SecurityScanStep` 경로 헬퍼 + 사후 필터 (4.2)
4. [x] `scan_mode`/`findings_before_filter`/elapsed 로깅 (4.4)
5. [x] `secscan.yml` checkout + diff + jq body, `SECSCAN_SELECTIVE` 게이트 (4.3)
6. [x] 단위 테스트 11건 + 기존 stub 갱신 → **112 passed**
7. [ ] 라이브 PR에서 selective 모드 실측 — **환경 작업(11월 §4.4)**

### 코드 작업 완료분 (이 브랜치 `dev/Github-issue-4`)
- `app/schemas/pipeline.py`, `app/api/v1/pipelines.py`,
  `app/services/pipeline/{pipeline_service,pipeline_runner,step_executor}.py`,
  `app/services/pipeline/steps/security_scan_step.py`
- `docs/templates/secscan.yml` — diff 전달 게이트
- `tests/unit/services/test_security_scan_step_selective.py` (신규) + 기존 테스트 갱신

### 남은 환경 작업 (코드 외)
- 대상 리포 Variables에 `SECSCAN_SELECTIVE=true` 추가 → 라이브 PR로 selective 동작 확인
- 같은 PR selective/full 2회 실행해 §4.4 비교 데이터 수집(11월)

---

## 미결정 / 리스크

- **시간 이득 미검증** — 사후 필터라 semgrep 자체는 전체를 스캔한다. 순수 스캔 시간 단축이 아니라
  finding/AI/회신 단계의 절감 + "변경분 집중" 신호가 1차 가치. 실제 시간 이득은 §4.4 실측으로 판정.
- **경로 정합성** — `git diff` 상대경로 ↔ semgrep 절대경로 환원이 어긋나면 매칭 실패(조용히 0건).
  `repo_root_path` 기준으로 환원하며, 대소문자는 보존(리눅스 컨테이너 기준 case-sensitive).
- **모노레포/서브디렉터리** — `detect_project_root`로 실행 경로가 하위로 내려가도 매칭은 클론 루트(`repo_root_path`)
  기준이라 `git diff` 경로와 일치. 단, 대상 리포 레이아웃이 특이하면 11월 실측에서 재확인.
- **선택적의 함정** — 변경 파일만 보면 "변경되지 않은 기존 취약점"은 못 잡는다. 그래서 **기본은 전수**,
  selective는 명시적 opt-in으로 유지.
