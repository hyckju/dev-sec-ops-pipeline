# Phase 1 — CI/CD 인터페이스 (작업 일지)

작성: 2026-06-01
관련 문서: [`progress-and-roadmap.md`](./progress-and-roadmap.md), [`phase-0-test-foundation.md`](./phase-0-test-foundation.md)

---

## 목적 (왜 이 작업을 했는가)

Phase 0에서 만든 API 계약 테스트(83 passed + 8 skipped)를 안전망 삼아, 백엔드를 **외부 CI/CD(GitHub Actions)에서 실제로 호출 가능한 형태**로 다듬었다. Phase 2(워크플로 작성)가 의존할 인터페이스 — 인증, 컨테이너 이미지, 가벼운 폴링 엔드포인트, 집계 필드 — 를 먼저 갖추는 것이 목표.

이번 세션 범위: **1.1~1.4 코드 작업만**. 신규 코드 테스트와 `SecurityScanException` 정리는 의도적으로 분리(다음 세션). 1.5 배포 위치는 의사결정 항목으로 코드 아님.

---

## 결과 한눈에

- 4개 작업(1.1~1.4) 구현 완료 + **신규 코드 테스트 11개 추가**, **회귀 0** — pytest **94 passed + 8 skipped**
- 신규 라우트 `/api/v1/pipelines/{id}/status` 등록 확인, `PipelineDetailResponse.summary` 필드 추가 확인
- 신규 코드 안전망: `verify_api_key` 단위 5건 + `/status`·`summary`·인증 통합 6건 (2026-06-01 마무리 세션)

---

## 파일별 결정 노트

### 1.1 API 키 인증

- `app/core/config.py` — `API_KEY: str = ""` 추가.
- `app/api/deps.py` — `verify_api_key(x_api_key: Header(alias="X-API-Key"))` 의존성.
- `app/api/v1/pipelines.py` — `router = APIRouter(dependencies=[Depends(verify_api_key)])`로 **모든 파이프라인 엔드포인트 일괄 보호**.
- `.env.example` — `API_KEY=` + 설명 주석.

**핵심 설계 — "키 설정 시에만 강제"**:
`settings.API_KEY`가 비어 있으면 `verify_api_key`가 즉시 통과한다. 이유:
- 개발/ngrok 1차 검증 단계에서 키 없이 바로 쓸 수 있음.
- Phase 0의 계약 테스트 13개가 키 없이 호출하는데, **테스트 코드 수정 없이** 그대로 통과(회귀 0).
- 운영 배포 시 `.env`에 `API_KEY`만 채우면 즉시 인증 활성화.

**범위 한정**: `/health`와 `projects` 라우터는 이번에 미보호로 남김(로드맵이 pipelines만 명시). 추후 동일 의존성 적용 가능.

### 1.2 Dockerfile + .dockerignore

- `backend/Dockerfile` — `python:3.11-slim` 기반. `git` 설치(clone 스텝 필수), requirements 레이어 캐시, 비루트 사용자(`appuser`), `uvicorn app.main:app` CMD.
- `backend/.dockerignore` — **필수**. `.venv/`(수백 MB)·`__pycache__`·`.pytest_cache`·`tests/`·`.env`·`.idea/` 제외. 없으면 `COPY . .`가 venv를 통째로 복사해 이미지가 비대해짐.
- DB는 외부(`DATABASE_URL` 주입), `WORKSPACE_DIR` 기본값 `/tmp/...`는 리눅스 컨테이너에서 그대로 동작.

### 1.3 status 폴링 엔드포인트

- `schemas/pipeline.py` — `PipelineStatusResponse` 신규.
- `pipelines.py` — `GET /{id}/status`.

**설계 의도 — "가벼움"**: GitHub Action이 30초 간격 폴링하므로 전체 vulnerabilities를 직렬화하지 않는다.
- `vulnerability_count`는 `select(func.count())`로 **카운트만** (행 로드 X).
- 진행 단계는 `pipeline.steps`(JSON 배열) 끝 항목에서 도출: `current_step = steps[-1]["type"]`, `completed_steps = len(steps)`, `total_steps = 6`.

### 1.4 summary 필드

- `schemas/pipeline.py` — `PipelineSummary {critical, high, medium, low, info, kev_count}`, `PipelineDetailResponse.summary` 추가.
- `pipelines.py` — `get_pipeline`이 KEV 주입 후 집계해 반환.

**재사용 결정 (중복 제거)**: 기존 `/vulnerabilities` 엔드포인트의 KEV 주입 로직(cve_id → CveCatalog 조인 → `kev_listed` 주입, 약 18줄)을 모듈 함수 `_build_vuln_responses(db, vulns)`로 추출해 **두 엔드포인트가 공유**. summary 집계는 `_build_summary(responses)`로 분리.
- `get_pipeline`: `model_validate(pipeline)` → `vulnerabilities`/`summary`를 주입값으로 덮어쓰기. (`summary`는 ORM에 없는 속성이라 기본값으로 검증 통과 후 교체.)
- `kev_count`가 의미를 가지려면 상세 조회에서도 KEV 조인이 필요 → 그래서 헬퍼 공유가 자연스러웠음.

---

## 검증

```bash
cd backend
./.venv/Scripts/python.exe -m pytest -q     # 83 passed, 8 skipped — 회귀 0
```

import/라우트 스모크:
```bash
./.venv/Scripts/python.exe -c "from app.main import app; print([r.path for r in app.routes if hasattr(r,'path')])"
# /api/v1/pipelines/{pipeline_id}/status 등록 확인
```

**미수행(환경 의존)**: DB 연동 수동 스모크(POST→폴링→summary)와 `docker build`는 postgres/도커 환경에서 별도 확인 필요. 빌드 자체는 .dockerignore로 venv 제외됨.

---

## 다음 해야 할 일

우선순위 순. ①②는 Phase 1 마무리, ③부터 Phase 2.

### ① 신규 코드 테스트 작성 ✅ 완료 (2026-06-01)

Phase 0 안전망을 신규 코드까지 확장. 11건 추가, 전체 94 passed + 8 skipped (회귀 0).

- `tests/unit/api/test_deps_auth.py` (신규, 5건) — `verify_api_key` 단위 테스트
  - `API_KEY` 미설정 → 헤더 없어도/있어도 통과 (2건)
  - `API_KEY` 설정 + 헤더 누락/불일치 → 401 (2건)
  - `API_KEY` 설정 + 헤더 일치 → 통과 (1건)
- `tests/integration/pipeline/test_pipelines_api.py` 보강 (6건)
  - `GET /{id}/status` — 404, 200 응답 스키마(`current_step`/`completed_steps`/`vulnerability_count`), vulnerabilities 미포함, steps 빈 경우 (3건)
  - `GET /{id}` `summary` 필드 — severity 카운트 합 == vulnerabilities 길이, `kev_count` 주입 (1건)
  - 인증 활성(`monkeypatch settings.API_KEY`) 시 401 / 헤더 일치 통과 (2건) — `monkeypatch` 자동 복원으로 기존 키-미설정 테스트와 격리됨

### ② Phase 1 마무리 잔여

- **1.5 백엔드 배포 위치 결정** (의사결정 대기, 로드맵 §4.1) — 권장: 1차 ngrok 검증 → 8~9월 영구 배포(EC2/Oracle/학교 서버)
- DB/도커 환경에서 수동 검증: `docker build`, `POST → /status 폴링 → summary` 스모크
- (선택) `SecurityScanException` 정리 — 보류 유지. Phase 2에서 차단 정책 다룰 때 함께 처리 고려

### ③ Phase 2 — GitHub Actions 워크플로 (status/summary 인터페이스 위에서 착수)

이번에 만든 `/status`(폴링)와 `summary`(코멘트용)가 여기서 처음 소비된다.

- `.github/workflows/secscan.yml` (대상 리포에 들어갈 파일)
  - `curl POST /api/v1/pipelines/` (+ `X-API-Key` 헤더) → `pipeline_id` 수신
  - 30초 간격 `GET /{id}/status` 폴링 → `status`가 success/failed 될 때까지 대기
  - `secrets.SECSCAN_API_KEY` / 백엔드 URL을 리포 시크릿으로 주입
- PR 코멘트 회신 (`actions/github-script@v7`) — `GET /{id}` 의 `summary`로 마크다운 표 작성
- 차단 정책 분기 — 로드맵 §4.2 미결(11월 실증 후 결정). 우선 **리포팅만**, 워크플로 fail 안 함
- WebGoat 등 의도적 취약 리포로 1라운드 검증
- `tests/integration/github/test_action_contract.py` — Action이 의존하는 응답 필드 스키마 snapshot (Phase 0에서 보류했던 것)

### 기타 백로그

| 항목 | 메모 |
|---|---|
| `projects` 라우터 인증 | 필요 시 `verify_api_key` 동일 적용 |
| semgrep 바이너리 dev 의존성화 | Phase 0의 8 skipped 활성화 (룰팩 회귀 감지) |
| `.idea/` gitignore 정리 | Phase 0 일지 §4 — 브랜치 전환 차단 재발 방지 |
