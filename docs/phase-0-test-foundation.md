# Phase 0 — 테스트 토대 완료 (작업 일지)

작성: 2026-05-31
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
