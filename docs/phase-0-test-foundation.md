# Phase 0 — 테스트 토대 완료 (작업 일지)

작성: 2026-05-31 (Git/PR 준비 섹션 추가)
작업 기간: 2026-05-28 ~ 2026-05-31

관련 문서: [`progress-and-roadmap.md`](./progress-and-roadmap.md), [`security-scan-feature.md`](./security-scan-feature.md)

---

## 목적 (왜 이 작업을 했는가)

CI/CD 통합(Phase 1~2)에 들어가기 전, **외부에서 호출할 API 계약**과 **보안 엔진 정확도**를 회귀로부터 보호하는 안전망을 만드는 게 목적.
신청서 10월 GitHub Actions 통합, 11월 기업 실증 단계에서 이 안전망이 없으면 변경할 때마다 손으로 확인해야 함.

---

## 결과 한눈에

- **총 91 테스트 수집**: 83 passed + 8 skipped (1.6s 내외)
- **신규 6개 CWE 골든 픽스처** — 11월 정확도 측정용 시드
- **환경 이슈 3건 해결** (아래 트러블슈팅 섹션)

```
tests\integration\pipeline\test_pipelines_api.py .............           [ 14%]
tests\integration\security\test_cwe_scan_golden.py .ssssssss             [ 24%]
tests\unit\services\test_cve_service.py .......................          [ 49%]
tests\unit\services\test_pipeline_runner.py .............                [ 63%]
tests\unit\services\test_semgrep_service.py ............................ [ 94%]
.....                                                                    [100%]
```

실행:
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

---

## 파일별 결정 노트

### `backend/tests/conftest.py` (픽스처 + autouse reset)

- `_reset_cve_module_caches` — autouse로 매 테스트마다 `_CWE_CVE_CACHE`와 `_kev_cache`를 비움.
  **왜**: 모듈 전역 캐시가 테스트 간 상태를 흘리면 순서 의존성이 생김 (다른 테스트가 캐시 채워두면 내 테스트가 NVD 호출 mock 안 해도 통과해버림).
- 샘플 데이터 픽스처 3종 (`sample_nvd_cve_item`, `sample_parsed_cve`, `sample_semgrep_finding`) — 여러 테스트에서 재사용.

### `tests/unit/services/test_semgrep_service.py` (33 tests)

- `_make_semgrep_service_with_mocks` 헬퍼로 runner/parser 양쪽을 mock — 진짜 semgrep 호출 없이 enrichment 로직만 검증.
- CWE_SCAN_CONFIG 6개 CWE 모두 rules/filter_keywords/label 보유 검증 (구조 회귀 방지).
- `_match_cve` 라운드로빈/severity-pool/fallback 케이스 분리.

### `tests/unit/services/test_cve_service.py` (23 tests)

- NVD JSON 파싱: CVSS v3.1 → v3.0 폴백, CWE-NOINFO 무시.
- 캐시 hit/miss/만료 세 갈래.
- CISA KEV 피드: 정상 파싱 + 실패 처리.

### `tests/integration/pipeline/test_pipelines_api.py` (13 tests)

- **ASGITransport + AsyncClient in-memory 호출** — 별도 서버 띄우지 않음, lifespan도 실행 안 함.
- `app.dependency_overrides[get_db]`로 DB 의존성 mock 주입.
- `PipelineService.create_and_run`을 stub해서 백그라운드 태스크 안 돌리고 라우터 입출력 계약만 본다.
- 검증: 202 응답 스키마, 422 검증 4종(비-HTTP URL / 빈 cve_fields / 5개 초과 / Enum 외), 중복 cve_field 자동 제거, vulnerabilities 필터 파라미터 6종.

### `tests/unit/services/test_pipeline_runner.py` (13 tests, 본 세션 신규)

**핵심 의도** (로드맵 §3 Phase 0):
- clone 실패 → 즉시 중단
- install/test 실패해도 scan까지 진행
- finalize 호출 보장

**설계 결정**:
- `_patch_executor(runner, results_by_step)` 헬퍼 — `StepExecutor.execute`를 step_type → StepResult 매핑으로 mock하고 호출 순서를 list로 기록. 6 step 순서/생략 검증을 한 번에.
- detectors/tempfile/shutil/console 전부 monkeypatch — 디스크 부수효과 0.
- `_fetch_pipeline`을 class-level monkeypatch — Pipeline 모델 conftext 우회.
- `_save_vulnerabilities`도 patch — DB 호출 사실만 추적, 별도 단위 검증 대상 아님.

**SQLAlchemy 매퍼 이슈** (잡고 가는 데 시간 좀 씀):
- `Pipeline()` 인스턴스화 시 `Project` 등 relationship target 클래스가 매퍼에 등록되어 있어야 함.
- `app/db/models/__init__.py`가 비어있어서 명시 import 안 하면 InvalidRequestError.
- 해결: 테스트 파일 상단에서 `from app.db.models import project, vulnerability, report, cve_catalog` (전체 모델 강제 로드).
- **개선 여지**: `__init__.py`에서 모든 모델 re-export하면 보일러플레이트 사라짐. 다음 테스트 작성 시 또 마주칠 문제.

### `tests/integration/security/test_cwe_scan_golden.py` (1 + 8 skipped, 본 세션 신규)

**핵심 의도**: 6개 CWE 의도적 취약 픽스처에 대해 `SemgrepService.run_cwe_scan`이 모두 정탐하는지 검증.

**설계 결정**:
- **module-scoped fixture로 semgrep 1회만 호출** — semgrep 실행이 무거움(룰팩 다운로드 30s+). 6개 CWE를 한 번 스캔하고 6개 parametrize 테스트가 결과 공유.
- **`skipif(not shutil.which("semgrep"))`** — 모듈 레벨이 아니라 개별 적용. sanity check (디렉토리 존재 확인)는 semgrep 없어도 항상 실행 → 픽스처 삭제/이동 즉시 가시화.
- **try/except → pytest.skip 변환** — semgrep이 설치되어 있어도 인증/네트워크 실패하면 ERROR 아니라 SKIPPED로 처리.
- **`RUN_SEMGREP_GOLDEN=1` 환경 변수**로 강제 실행 모드 제공 — 11월 실증 직전에 진짜 정확도 검증할 때 사용.
- **finding의 file_path가 기대 서브디렉토리에 속하는지 검증** — CWE-89 finding이 CWE-78 폴더에서 잡히면 fail. 오탐/잘못된 필터링 회귀 방지.

### `backend/tests/integration/security/fixtures/cwe_golden/` (신규, 11월 시드)

6개 CWE 각각에 전용 서브디렉토리 + 의도적 취약 코드:

| CWE | 파일 | 패턴 |
|---|---|---|
| CWE-89 SQL Injection | `cwe_89_sql_injection/vulnerable.py` | f-string SQL, 문자열 연결, str.format |
| CWE-79 XSS | `cwe_79_xss/vulnerable.py` | raw HTML 삽입, jinja autoescape off, Markup 우회 |
| CWE-22 Path Traversal | `cwe_22_path_traversal/Vulnerable.java` | Servlet 파라미터 → 파일 경로 조립 |
| CWE-918 SSRF | `cwe_918_ssrf/Vulnerable.java` | Servlet 파라미터 → URL fetch |
| CWE-78 Command Injection | `cwe_78_command_injection/vulnerable.py` | os.system / subprocess shell=True / os.popen |
| CWE-798 Hardcoded Credentials | `cwe_798_hardcoded_credentials/vulnerable.py` | AWS/GitHub/Stripe/Slack 키 + 평문 패스워드 |

**왜 서브디렉토리로 분리?** 픽스처별로 어떤 CWE를 의도했는지 명확해지고, 위 정합성 테스트가 가능해짐.

---

## 환경 트러블슈팅 기록 (다음에 또 만날 수 있음)

### 1. SQLAlchemy `One or more mappers failed to initialize`

증상: `Pipeline()` 호출에서 `'Project' failed to locate a name` 에러.

원인: `app/db/models/__init__.py`가 비어있어 의존 모델이 매퍼에 등록 안 됨.

해결: 테스트 파일 상단에서 명시 import. 또는 (장기) `__init__.py`에서 re-export.

### 2. IntelliJ가 시스템 Python을 씀

증상: pytest 실행 시 trace에 `C:\Users\user\AppData\Local\python\pythoncore-3.14-64\` 경로. `httpx`, `pydantic_settings` ModuleNotFoundError.

원인: `.idea/misc.xml`이 `project-jdk-name="openjdk-23"`, `JavaSDK`로 잡혀 있어서 Python interpreter 자동 인식 안 됨. Run Configuration이 시스템 Python으로 폴백.

해결:
1. `Project Structure → SDKs → +` → "디스크에서 추가" → `backend/.venv/Scripts/python.exe`
2. `Project Structure → Modules → Module SDK`에서 위 venv SDK 선택
3. 기존 잘못된 Run Configuration 삭제 후 재생성

### 3. venv 안 가짜 `app/` 패키지 (가장 헷갈렸음)

증상: `from app.services.security.semgrep_service import ...`가 `werkzeug.utils.ImportStringError: import_string() failed for 'config'`로 실패.

원인: `backend/.venv/Lib/site-packages/app/__init__.py`에 Flask 보일러플레이트가 들어있어 우리 프로젝트의 `backend/app/`를 가림. IntelliJ Flask wizard가 venv에 잘못 생성한 것으로 추정 (오늘 23:46 생성, pip 등록 안 됨).

해결:
```bash
rm -rf backend/.venv/Lib/site-packages/app
```

**예방**: IntelliJ에서 Python 모듈 추가 시 Flask facet 자동 추가 옵션 끄거나, venv 안에 들어가는 변경은 의심.

### 4. `.idea/workspace.xml` 브랜치 전환 차단

증상: `git checkout tst/Github-issue-1` 시 `error: Your local changes to the following files would be overwritten by checkout: .idea/workspace.xml`.

원인: 파일이 main에는 존재하고 tst에는 없음 + 사용자가 IDE 사용 중 자동 수정. 덮어쓰면 변경분 손실되니 git이 거부.

해결: IDE 런타임 상태 파일이라 그냥 버려도 IntelliJ가 재생성.
```powershell
git checkout -- .idea/workspace.xml
git checkout tst/Github-issue-1
```

**예방 (장기)**: `.idea/workspace.xml`을 `.gitignore`에 추가. 더 적극적으로는 `.idea/` 전체 + `!.idea/.gitignore` (JetBrains 권장 패턴). 의사결정 대기 항목 참조.

---

## Git 작업 및 PR 준비 (2026-05-31)

테스트 코드를 GitHub에 올리려다 만난 두 가지 차단을 정리.

### 차단 1: GitHub push protection (Stripe / Slack 패턴)

증상: 첫 push 시 GitHub가 `8e9c849f72cc341e...` 커밋에서 secret 탐지로 거부.
- `cwe_798_hardcoded_credentials/vulnerable.py:19` — Stripe `sk_live_*` 패턴
- `vulnerable.py:23` — Slack webhook URL (`https://hooks.slack.com/services/...`)

**역설적인 상황**: 픽스처가 의도대로 작동했다는 증거(=실제 secret처럼 보임)인데, 너무 잘 작동해서 GitHub의 자체 scanner도 잡아버린 것.

해결 (두 단계):

**a) 픽스처 수정** — service-specific prefix 제거, semgrep `generic-api-key` 패턴으로 대체:
- ❌ `STRIPE_API_KEY = "sk_live_..."`, `SLACK_WEBHOOK = "https://hooks.slack.com/..."`
- ✅ `PAYMENT_GATEWAY_API_KEY`, `THIRD_PARTY_API_TOKEN`, `INTERNAL_WEBHOOK_SECRET` 등 generic 변수명 + 가짜 값
- 변수명만으로도 semgrep p/secrets의 generic 룰이 발동하므로 탐지 의도 보존
- docstring에 금지 패턴 명시 (`sk_live_*`, Slack webhook URL) — 재발 방지

**b) 히스토리 정리** — fix를 별도 커밋(`ace81c6`)으로 쌓았다가 *원본 커밋(`8e9c849`)에 secret이 그대로 남아있어* 재차 거부됨. GitHub는 push되는 *모든 커밋*을 스캔하기 때문.
```powershell
git reset --soft HEAD~2      # 두 커밋을 staging으로 되돌림 (작업물 보존)
git commit -m "test: Phase 0 ..."   # 단일 깨끗한 커밋으로 재구성
git push                     # 성공 (커밋 70be3f0)
```

**교훈**: secret 패턴 실수했을 때 fix를 위 커밋으로 쌓지 말 것. `amend` 또는 `soft reset + 재커밋`으로 원본 커밋 자체를 갈아치워야 함.

### 차단 2: PR 생성 불가 (unrelated histories)

증상: tst → main PR 만들려 했더니 GitHub UI가 비교 불가 상태.

원인: GitHub 리포 생성 시 자동 추가된 `724d927 Initial commit (LICENSE만)`이 origin/main의 유일한 커밋. 로컬 작업은 그와 무관하게 `f9e68af`부터 시작한 별개 히스토리. 두 갈래 사이 공통 조상이 없음.

해결: LICENSE 보존하면서 origin/main을 로컬 main으로 force-push.
```powershell
git checkout origin/main -- LICENSE              # LICENSE만 로컬에 가져옴
git commit --only LICENSE -m "chore: ..."        # LICENSE 단독 커밋 (ccba503)
git push origin main --force                      # origin/main 덮어쓰기
```

이제 main과 tst가 `5ee0c45`를 공통 조상으로 공유 → PR diff는 `70be3f0` 한 커밋만 깨끗하게 노출.

**왜 LICENSE는 main에 직접 푸시했나**: tst 브랜치는 Phase 0 작업 전용. LICENSE는 인프라성 fix라 거기 섞으면 PR diff에 무관한 변경이 들어감. main에 직접 두는 게 의미상 정확. (엄격한 GitFlow였다면 별도 `chore/license` 브랜치 + PR로 처리.)

### 최종 상태

```
origin/main:                 ccba503 (chore: LICENSE)
                             d805431 (.idea 사용자 커밋)
                             5ee0c45 ← 공통 조상
                             8984f41
                             f9e68af

origin/tst/Github-issue-1:   70be3f0 (Phase 0, 26 files, 2050 insertions)
                             5ee0c45 ← 공통 조상
                             ...
```

- ✅ PR 생성 가능 (https://github.com/hyckju/dev-sec-ops-pipeline/compare/main...tst/Github-issue-1)
- ✅ working tree clean, `tst/Github-issue-1` 체크아웃 상태

---

## 의사결정 대기 항목 (Phase 1 진입 전 정리 필요)

### main.py — `SecurityScanException` 처리

현재 상태: `exceptions.py`에 정의는 있고 `main.py:6`에서 import도 함. 하지만:
- handler 등록 없음
- 코드베이스 어디서도 raise 안 함 (사실상 dead)
- `PipelineException`을 상속하지도 않아서 기존 handler가 잡지도 못함

세 갈래:
- **A**. handler 추가 (502 Bad Gateway? 503? semgrep registry 장애를 어떻게 표현할지)
- **B**. import만 제거 (당분간 사용 안 할 거면)
- **C**. `security_scan_step.py` / `semgrep_service.py`에서 `RuntimeError` 대신 raise — Phase 1 작업 자연스럽게 묶어서

현재 동작에는 무해. Phase 1 들어갈 때 C와 묶어 처리하는 게 자연스러움.

### 4.1 백엔드 배포 위치 (로드맵 §4.1)

- ngrok / EC2 / Oracle Cloud / 학교 서버
- 권장: Phase 1.1~1.4 코드 작업은 즉시 시작 + ngrok으로 1차 검증 → 8~9월에 영구 배포 전환

### 4.2 차단 정책 (로드맵 §4.2)

- 11월 실증 false positive 비율 측정 후 결정

### `tests/integration/github/test_action_contract.py`

Phase 2 (GitHub Actions 워크플로)와 함께 작성. 지금은 인터페이스 미정이라 보류.

### `.idea/` gitignore 정리

`.idea/workspace.xml`은 IDE 실행 중 계속 바뀌어 브랜치 전환마다 동일 차단 재발 가능 (트러블슈팅 §4 참조).

옵션:
- **A. `.idea/workspace.xml`만 ignore** — 기존 추적된 다른 `.idea/*.xml`은 유지
- **B. `.idea/` 전체 ignore + `!.idea/.gitignore` 예외** — JetBrains 권장 패턴, 가장 깔끔
- **C. 그냥 두기** — 매번 discard로 처리

이미 push된 `.idea/*` 파일들을 어떻게 할지(`git rm --cached`로 추적 해제할지)도 함께 결정 필요.

---

## 11월 실증 시 진짜 정확도 검증 활성화

지금 SKIPPED 8개를 진짜로 돌릴 때:

```powershell
cd backend
.\.venv\Scripts\semgrep.exe login            # 브라우저 인증
$env:RUN_SEMGREP_GOLDEN="1"                  # opt-in 강제 실행
.\.venv\Scripts\python.exe -m pytest tests/integration/security/ -v
```

이렇게 하면 6개 CWE 골든 픽스처에 대해 실제 semgrep 스캔이 돌고, 정탐/오탐 데이터가 보고서 raw data가 됨.

---

## 다음 작업 (Phase 1 진입)

| # | 작업 | 차단 요소 |
|---|---|---|
| 1.1 | API 키 인증 (`app/api/deps.py`에 `verify_api_key`) | 없음 |
| 1.2 | `backend/Dockerfile` 작성 | 없음 |
| 1.3 | `GET /api/v1/pipelines/{id}/status` 가벼운 폴링 엔드포인트 | 없음 |
| 1.4 | `PipelineDetailResponse.summary` 필드 추가 | 없음 |
| 1.5 | 백엔드 배포 위치 결정 | **4.1 의사결정 대기** |

1.1~1.4는 코드만 작성하면 됨. 1.5만 결정 필요. 1.5 결정 전이라도 1.1~1.4 진행 가능.
