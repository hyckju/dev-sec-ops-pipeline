# 진행 현황 및 로드맵 (CI/CD 보안 파이프라인)

마지막 업데이트: 2026-06-02

관련 문서
- 현재 구현 명세: [`security-scan-feature.md`](./security-scan-feature.md)
- Phase 0 완료 보고서 (테스트 토대): [`phase-0-test-foundation.md`](./phase-0-test-foundation.md)
- 일정 원본: `../2026학년도 C-리빙랩 프로젝트 참여신청서 .hwpx`

---

## 1. 한 줄 요약

백엔드 보안 스캔 엔진(6단계 파이프라인 + Semgrep + NVD + AI 후처리)은 **선행 구현 완료**.
현재는 외부 CI/CD(GitHub Actions 등)에서 호출 가능한 형태로 다듬는 **준비 단계**.
Phase 0(테스트 토대) **부분 완료** (101 passed + 8 skipped, semgrep 환경 충족 시 109 전체).
Phase 1(CI/CD 인터페이스) **완료** — 인증·Dockerfile·status 엔드포인트·summary 필드(1.1~1.4) + 신규 코드 테스트 11건 + 1.5 배포 위치 결정(DockerHub 레지스트리).
Phase 2(GitHub Actions) **코드 작업 완료** — 계약 테스트 7건 + `docker-publish.yml` + `secscan.yml` 템플릿. 잔여는 환경 작업(시크릿·ngrok·WebGoat 검증)과 보류(차단 정책).

---

## 2. 신청서 일정 vs 실제 진척

| 월 | 계획 | 실제 상태 | 비고 |
|---|---|---|---|
| 4월 | 기업 요구사항/배포 환경 분석 | 완료 | 3월 초기 커밋으로 백엔드 구조 정립 |
| **5월** | **시스템 아키텍처 설계** | 부분 완료 | docs는 *구현 기준* 명세. 설계 산출물(다이어그램, 선택적 스캔 정책)은 보강 필요 |
| 6월 | NVD REST API 연동 + 캐싱 | 선행 완료 | `cve_service.py`, `cve_catalog` 모델 |
| 7월 | CWE 기반 분석 + 필터링 | 선행 완료 | `semgrep_service.py`의 6개 CWE 설정 |
| 8월 | 5종 취약점 탐지 고도화 + 속도 최적화 | 미시작 | 벤치마크 하네스 필요 |
| 9월 | 중간점검 + LLM 연동 | 선행 완료 | Claude/Gemini 후처리 권고 통합됨 |
| 10월 | GitHub Actions 등 CI/CD 통합 | 미시작 | **현재 작업 흐름의 목표** |
| 11월 | 기업 테스트베드 실증 (탐지 정확도/속도) + 경진대회 (11.24) | 미시작 | 측정용 골든 데이터셋 필요 |
| 12월 | 최종 보완 + 결과보고서 | 미시작 |  |

---

## 3. Phase 별 진행 상황 (CI/CD 통합 작업 흐름)

### Phase 0 — 테스트 토대 (진행 중)

CI/CD 통합 전제 조건. *외부에서 호출할 API 계약*과 *보안 엔진 정확도*를 회귀로부터 보호한다.

#### 완료된 항목

| 파일 | 테스트 수 | 검증 영역 |
|---|---|---|
| `backend/tests/conftest.py` | (픽스처 3 + autouse cache reset) | NVD/CVE 모듈 캐시 격리, 샘플 NVD/CVE/Semgrep 데이터 |
| `backend/tests/unit/services/test_semgrep_service.py` | 33 | `CWE_SCAN_CONFIG` 구조, severity 정규화, `_match_cve` (round-robin/severity-pool/fallback), semgrep error 감지, `run_cwe_scan` enrichment |
| `backend/tests/unit/services/test_cve_service.py` | 23 | language→keyword 매핑, `_extract_cwe_id`, `_parse_cve_item` (CVSS v3.1→v3.0 폴백, CWE-NOINFO 무시), `fetch_cves_by_cwe` 캐시 hit/miss/만료, CISA KEV 피드 파싱·실패 처리 |
| `backend/tests/integration/pipeline/test_pipelines_api.py` | 13 | `POST /pipelines/` 202 + 응답 스키마, 422 검증 4종 (비-HTTP url / 빈 cve_fields / 5개 초과 / Enum 외 값), 중복 cve_field 자동 제거, `GET /{id}` 404, malformed UUID 422, vulnerabilities 필터 파라미터 (severity/cwe_id/min_cvss/sort_by/sort_order/kev_only) |
| `backend/tests/unit/services/test_pipeline_runner.py` | 13 | 정상 6-step 순서 보장, clone metadata→pipeline 컬럼 전파, vulnerabilities 저장 호출, clone 실패 시 즉시 중단, install/test 실패해도 scan까지 진행, scan 실패 시 build/report 미실행, build 실패해도 report 실행, workspace cleanup (성공/실패/예외 경로 모두), pipeline 미존재 시 조기 return, 잘못된 UUID 흡수 |
| `backend/tests/integration/security/test_cwe_scan_golden.py` | 1 (+8 skipped) | 6개 CWE 골든 픽스처 디렉토리 sanity check (항상 실행) + 실제 semgrep 스캔으로 6개 CWE 정탐 / finding 필수 필드 / 픽스처 경로 정합성 검증 (semgrep 바이너리 있을 때만) |
| `backend/tests/integration/security/fixtures/cwe_golden/` | — | **11월 실증 정확도 데이터셋 시드**: 6개 CWE 의도적 취약 코드 (Python 4 + Java 2) |
| `backend/pyproject.toml` | — | `[tool.pytest.ini_options]` 추가 (`asyncio_mode=auto`, `testpaths=tests`) |
| `backend/requirements.txt` | — | pytest, pytest-asyncio 추가 |

**총 83 passed + 8 skipped (1.48s)** — skipped는 semgrep 바이너리 설치 시 자동 활성화

실행 명령:
```bash
cd backend
.venv/Scripts/python.exe -m pytest -v
```

#### 남은 작업

| 우선순위 | 파일 (예정) | 검증 영역 | 의의 |
|---|---|---|---|
| ~~중~~ ✅ | `tests/integration/github/test_action_contract.py` | GitHub Action이 의존할 응답 필드 스키마 snapshot | **완료 (2026-06-02, 7건)** — Phase 2와 함께 작성 |
| 하 | semgrep 바이너리를 dev 의존성에 추가 (`requirements-dev.txt` 신설 또는 `pyproject.toml` optional group) | `test_cwe_scan_golden.py`의 8 skipped 테스트 활성화 — 룰팩 회귀 즉시 감지 |

---

### Phase 1 — CI/CD 인터페이스 ✅ 완료 (2026-06-01)

외부에서 호출 가능한 형태로 백엔드를 다듬는다. Phase 0의 API 계약 테스트가 *회귀 안전망* 역할.

작업 일지: [`phase-1-cicd-interface.md`](./phase-1-cicd-interface.md)

| # | 작업 | 위치 | 상태 |
|---|---|---|---|
| 1.1 | API 키 인증 추가 | `app/api/deps.py`의 `verify_api_key` 의존성, `pipelines.py` 라우터에 적용 | ✅ 완료 (키 미설정 시 비활성) |
| 1.2 | Dockerfile 작성 | `backend/Dockerfile` + `backend/.dockerignore` | ✅ 완료 |
| 1.3 | 가벼운 상태 폴링 엔드포인트 | `GET /api/v1/pipelines/{id}/status` — status + 진행 단계 + vuln 카운트만 반환 (전체 vulnerabilities 직렬화 X) | ✅ 완료 |
| 1.4 | summary 필드 추가 | `PipelineDetailResponse.summary: {critical, high, medium, low, info, kev_count}` — PR 코멘트 작성용 | ✅ 완료 |
| 1.5 | 백엔드 배포 위치 결정 | 이미지 레지스트리 **DockerHub** 확정 (publish는 Phase 2 GitHub Actions 자동화) | ✅ 완료 — 런타임 호스트는 미정(4.1) |

> 신규 코드(인증/status/summary) 테스트 11건 추가 완료 (94 passed + 8 skipped). `SecurityScanException` 정리는 보류 유지(Phase 2 차단 정책 때). docker/DB 수동 스모크는 환경 준비 시 실행.

---

### Phase 2 — GitHub Actions 워크플로 ⏳ 코드 작업 완료 (2026-06-02)

구현 설계: [`phase-2-github-actions.md`](./phase-2-github-actions.md) — 워크플로 YAML, 시크릿, 구현 순서, 계약 테스트 정리.

| # | 작업 | 위치 | 상태 |
|---|---|---|---|
| 2.0 | `docker-publish.yml` (이미지 build & push) | `.github/workflows/docker-publish.yml` | ✅ 작성 완료 (시크릿 등록·publish는 환경 작업) |
| 2.1 | `secscan.yml` (대상 리포 배포 템플릿) | `docs/templates/secscan.yml` | ✅ 작성 완료 (trigger → poll → comment) |
| 2.2 | PR 코멘트 회신 | `secscan.yml` 마지막 step (`github-script@v7`, 마커로 중복 코멘트 갱신) | ✅ 작성 완료 |
| 2.3 | 차단 정책 분기 | `secscan.yml`에 `if: false` 자리표시 | ⏸ 보류 (정책 4.2, 11월 실측 후) |
| 2.4 | 테스트 리포 1라운드 검증 | WebGoat 등 의도적 취약 리포 | ⬜ 환경 작업 (ngrok 노출 + fork PR) |
| — | 계약 테스트 | `tests/integration/github/test_action_contract.py` | ✅ 7건 통과 |

> `secscan.yml`은 *스캔 대상 리포*에 복사해 쓰는 파일이라 이 리포의 활성 워크플로(`.github/workflows/`)가 아닌 `docs/templates/`에 보관(자기 PR마다 실행되지 않도록). 남은 환경 작업: DockerHub 시크릿 등록 → publish 확인, 백엔드 ngrok 노출 + `API_KEY` 설정, WebGoat fork에 템플릿 배치 후 PR 코멘트 확인.

부수 작업: `actionlint`로 YAML 린트, `act`(nektos/act)로 로컬 dry-run (러너 환경에서).

---

### Phase 3 — 선택적 분석 강화 (8월 계획, 신청서 핵심 차별점)

신청서 "선택적 분석" 정의를 실제 구현으로 채우는 단계.

| # | 작업 | 위치 |
|---|---|---|
| 3.1 | `PipelineCreate.changed_files: list[str] \| None` 필드 추가 | `schemas/pipeline.py` |
| 3.2 | `SecurityScanStep`이 `changed_files`만 스캔하도록 분기 | `security_scan_step.py` 루프에 파일 필터 추가 |
| 3.3 | Action이 `git diff --name-only origin/${{ github.base_ref }}...HEAD` 결과를 백엔드에 전달 | `secscan.yml` |
| 3.4 | "선택적 vs 전수" 시간/탐지수 비교 로깅 | 11월 실증 데이터 수집용 |

---

### Phase 4 — SARIF 출력 (옵션, 9~10월 계획, 기업 어필용)

| # | 작업 |
|---|---|
| 4.1 | Vulnerability → SARIF v2.1.0 변환기 작성 |
| 4.2 | `GET /pipelines/{id}/sarif` 엔드포인트 추가 |
| 4.3 | Action에 `github/codeql-action/upload-sarif@v3` 단계 추가 → GitHub Security 탭에 표시 |

---

## 4. 의사결정 대기 항목

### 4.1 백엔드 배포 위치 (Phase 1.5 — 레지스트리 결정 완료, 런타임 호스트 미정)

이미지 레지스트리는 **DockerHub로 확정**(이미지 저장/배포). 단, DockerHub는 레지스트리일 뿐이라
**이미지를 실제로 run할 런타임 호스트는 미정**. 외부 GitHub Action이 호출하려면 인터넷에서 닿는 URL이 필요하다. 후보:

| 후보 | 특징 | 적합 시기 |
|---|---|---|
| `ngrok http 8000` | 5분 셋업, 무료, URL이 매번 바뀜 | 개발 검증용 (즉시) |
| AWS EC2 free tier / Oracle Cloud Always Free / 학교 서버 | 안정적, 도메인 부여 가능 | 8~9월부터 |
| 클라우드에어 인프라 | 기업 환경 본격 적용 | 11월 실증 |

권장 진행: Phase 1.1~1.4 코드 작업은 지금 시작, 배포는 *ngrok으로 1차 검증* → 8~9월에 영구 배포 전환.

### 4.2 차단 정책 (Phase 2.3)

신청서는 "취약점 발견 시 자동 차단"을 명시하지만, 어느 심각도부터 차단할지는 *11월 실증에서 false positive 비율을 측정한 다음*에 결정해야 의미가 있다.

| 후보 | 운영 부담 | 신청서 정합성 |
|---|---|---|
| KEV 등재 CVE만 차단, 나머지는 경고 | 낮음 | 부분 충족 |
| Critical/High 탐지 시 모두 차단 | 높음 (false positive 다발) | 가장 충실 |
| 탐지하더라도 절대 차단 안 함 (리포팅만) | 없음 | 어긋남 |

권장 진행: 지금은 *전부 리포팅만* 하는 모드로 시작 → 11월 실증 데이터 보고 정책 확정 → 보고서에 근거 데이터로 활용.

### 4.3 5월 설계 산출물 보강

`docs/security-scan-feature.md`는 "현재 구현 기준" 명세로 표기되어 있어, 5월 마일스톤(*시스템 아키텍처 설계*)의 산출물로 인정받기 어렵다. 별도 설계 문서 작성 권장:
- 시스템 컴포넌트 다이어그램 (백엔드 ↔ Semgrep/NVD/AI ↔ DB ↔ 외부 CI)
- "선택적 분석"의 정의 (사용자 명시 CWE / git diff 변경분 / KEV 우선순위 중 채택안)
- 데이터 흐름 (PR 이벤트 → 파이프라인 실행 → 결과 회신)

---

## 5. 핵심 코드 위치 (참고)

| 영역 | 파일 |
|---|---|
| 오케스트레이션 | `backend/app/services/pipeline/pipeline_runner.py` |
| 보안 스캔 스텝 | `backend/app/services/pipeline/steps/security_scan_step.py` |
| Semgrep 통합 | `backend/app/services/security/semgrep_service.py`, `backend/app/integrations/semgrep/` |
| CVE/NVD 통합 | `backend/app/services/security/cve_service.py`, `backend/app/integrations/nvd/client.py` |
| AI 후처리 | `backend/app/integrations/gemini/client.py` |
| API 라우터 | `backend/app/api/v1/pipelines.py` |
| 스키마 | `backend/app/schemas/pipeline.py` |
| DB 모델 | `backend/app/db/models/` (pipeline, vulnerability, cve_catalog, project, report) |
| 테스트 | `backend/tests/` (unit, integration, e2e 하위 구조) |
