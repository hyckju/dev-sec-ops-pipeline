# Phase 3 — GitHub Actions 워크플로 (구현 설계)

작성: 2026-06-02
관련 문서: [`phase-2-cicd-interface.md`](./phase-2-cicd-interface.md), [`progress-and-roadmap.md`](./progress-and-roadmap.md)
상태: **코드 작업 완료** — 계약 테스트(7건) + 두 워크플로 작성·`actionlint` 통과(2026-06-03). 차단 정책은 `SECSCAN_ENFORCE` 변수 게이트로 자리 마련(정책 택1만 11월 실측 후). 잔여는 순수 환경 작업(시크릿 등록·ngrok·WebGoat 라이브 검증).

---

## 목적

Phase 2에서 만든 인터페이스(`POST /pipelines`, `GET /{id}/status`, `GET /{id}` 의 `summary`)를
**실제 GitHub Actions에서 소비**한다. 두 개의 분리된 워크플로로 구성:

1. **`docker-publish.yml`** (이 리포) — Phase 2.5 결정(DockerHub) 구현. 백엔드 이미지 build → push.
2. **`secscan.yml`** (스캔 대상 리포에 배치) — PR 이벤트 → 백엔드 호출 → 폴링 → PR 코멘트.

이 둘은 **독립적**이다. ①은 "백엔드를 어디에 둘 이미지로 만드나", ②는 "그 백엔드를 어떻게 호출하나".

---

## 전제 — 워크플로가 의존하는 API 계약

Phase 2에서 고정한 계약. 모든 경로 프리픽스는 `/api/v1/pipelines`. 인증은 `X-API-Key` 헤더
(`settings.API_KEY` 설정 시 강제, 미설정 시 통과).

| 호출 | 메서드 | 응답에서 쓰는 필드 |
|---|---|---|
| `/api/v1/pipelines/` | POST `{github_url}` → 202 | `id` (이후 폴링 키) |
| `/api/v1/pipelines/{id}/status` | GET | `status`, `current_step`, `completed_steps`, `total_steps`, `vulnerability_count` |
| `/api/v1/pipelines/{id}` | GET | `summary.{critical,high,medium,low,info,kev_count}`, `vulnerabilities[]` |

`status` 종료 상태: `success` / `failed` / `cancelled` (그 외 `pending`/`running`은 진행 중).

> ⚠️ 이 계약이 깨지면 Action이 조용히 실패한다 → 아래 **계약 테스트**로 고정한다.

---

## 3.0 `docker-publish.yml` — 이미지 build & push (2.5 구현)

**위치**: 이 리포 `.github/workflows/docker-publish.yml`
**트리거**: `main` push + 태그(`v*`) + 수동(`workflow_dispatch`). `backend/**` 변경 시에만.

```yaml
name: Publish backend image

on:
  push:
    branches: [main]
    tags: ['v*']
    paths: ['backend/**', '.github/workflows/docker-publish.yml']
  workflow_dispatch:

jobs:
  build-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}     # Read/Write 액세스 토큰 (계정 비번 X)
      - id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ secrets.DOCKERHUB_USERNAME }}/devsecops-backend
          tags: |
            type=ref,event=branch
            type=ref,event=tag
            type=sha
            type=raw,value=latest,enable={{is_default_branch}}
      - uses: docker/build-push-action@v6
        with:
          context: ./backend
          file: ./backend/Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**구현 메모**
- `context: ./backend` — Dockerfile이 `backend/`에 있고 `.dockerignore`가 venv를 제외(2.2).
- 런타임 호스트 미정이라 **여기서는 deploy 안 함**. 호스트 확정 후 별 잡(SSH `docker pull && run`,
  또는 watchtower/webhook)으로 이어붙인다.
- 이미지 이름 `devsecops-backend`는 예시. DockerHub 리포명 확정 시 교체.

---

## 3.1 `secscan.yml` — 스캔 호출 워크플로 (3.1)

**위치**: 스캔 대상 리포 `.github/workflows/secscan.yml` (이 리포가 아님 — 사용자 프로젝트에 배포).
**트리거**: `pull_request` (+ 수동). 3단계: **trigger → poll → comment**.

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  pull-requests: write   # 3.2 PR 코멘트용
  contents: read

jobs:
  secscan:
    runs-on: ubuntu-latest
    env:
      API: ${{ secrets.SECSCAN_BACKEND_URL }}   # 예: https://xxxx.ngrok-free.app
      KEY: ${{ secrets.SECSCAN_API_KEY }}
    steps:
      - name: Trigger pipeline
        id: trigger
        run: |
          resp=$(curl -fsS -X POST "$API/api/v1/pipelines/" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $KEY" \
            -d "{\"github_url\": \"${{ github.server_url }}/${{ github.repository }}\"}")
          id=$(echo "$resp" | jq -r '.id')
          echo "pipeline_id=$id" >> "$GITHUB_OUTPUT"
          echo "::notice::pipeline $id created"

      - name: Poll status (30s 간격, 최대 30분)
        id: poll
        run: |
          PID=${{ steps.trigger.outputs.pipeline_id }}
          for i in $(seq 1 60); do
            st=$(curl -fsS "$API/api/v1/pipelines/$PID/status" -H "X-API-Key: $KEY")
            status=$(echo "$st" | jq -r '.status')
            echo "[$i] status=$status step=$(echo "$st" | jq -r '.current_step') \
                 ($(echo "$st" | jq -r '.completed_steps')/$(echo "$st" | jq -r '.total_steps'))"
            case "$status" in
              success|failed|cancelled)
                echo "final=$status" >> "$GITHUB_OUTPUT"; exit 0 ;;
            esac
            sleep 30
          done
          echo "final=timeout" >> "$GITHUB_OUTPUT"; exit 1

      - name: Fetch detail (summary)
        if: always() && steps.trigger.outputs.pipeline_id != ''
        run: |
          PID=${{ steps.trigger.outputs.pipeline_id }}
          curl -fsS "$API/api/v1/pipelines/$PID" -H "X-API-Key: $KEY" > detail.json

      - name: Comment on PR
        if: always() && github.event_name == 'pull_request' && hashFiles('detail.json') != ''
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const d = JSON.parse(fs.readFileSync('detail.json', 'utf8'));
            const s = d.summary || {};
            const body = [
              '## 🔒 보안 스캔 결과',
              '',
              `상태: **${d.status}** · 취약점 ${ (d.vulnerabilities||[]).length }건`,
              '',
              '| Critical | High | Medium | Low | Info | KEV |',
              '|---:|---:|---:|---:|---:|---:|',
              `| ${s.critical||0} | ${s.high||0} | ${s.medium||0} | ${s.low||0} | ${s.info||0} | ${s.kev_count||0} |`,
              '',
              '<sub>DevSecOps Pipeline · 리포팅 모드 (차단 없음)</sub>',
            ].join('\n');
            await github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
```

**구현 메모**
- `curl -f` — 4xx/5xx 시 step 실패. 인증 401(키 불일치)도 여기서 잡힌다.
- `jq`는 ubuntu-latest 러너에 기본 설치됨.
- 폴링 타임아웃 30분은 가정값. 실측(11월) 후 조정.
- `github.repository`는 `owner/repo` → 전체 URL은 `github.server_url`과 합성.
- **프라이빗 리포** 스캔 시 백엔드 clone에 토큰 필요 → Phase 4 이후 과제(지금은 공개 리포 가정).

---

## 3.2 PR 코멘트 (3.2)

위 `secscan.yml`의 마지막 step에 통합(`actions/github-script@v7`). 별도 워크플로 아님.
- `summary`(2.4)로 severity 표 작성. `permissions: pull-requests: write` 필수.
- **중복 코멘트 정리**(선택): 매 push마다 새 코멘트 대신, 봇 코멘트를 찾아 `updateComment`로 갱신.
  1차 구현은 단순 `createComment`, 노이즈 보이면 업데이트 방식으로 개선.

---

## 3.3 차단 정책 (3.3) — **지금은 리포팅만**

로드맵 §4.2 미결(11월 실증 후 결정). **현재는 워크플로를 fail시키지 않는다.**
- `poll` step의 `success/failed`는 "파이프라인 실행 결과"이지 "차단 판정"이 아님 → comment까지 돌고 green.
- 향후 차단 활성화 지점은 **리포 변수 `SECSCAN_ENFORCE`로 게이트** — 파일 수정 없이 리포 설정만으로 on/off:

```yaml
      - name: (FUTURE) Enforce policy
        if: always() && vars.SECSCAN_ENFORCE == 'true' && hashFiles('detail.json') != ''
        run: |
          kev=$(jq -r '.summary.kev_count // 0' detail.json)
          if [ "$kev" -gt 0 ]; then echo "::error::KEV $kev건"; exit 1; fi
```

- 활성화: 대상 리포 Settings → Secrets and variables → Actions → **Variables**에 `SECSCAN_ENFORCE=true` 추가.
  변수 미설정이면 step이 skip되어 리포팅 모드 유지(actionlint도 통과 — `if: false` 상수식 경고 회피).
- 후보 정책: KEV만 차단 / Critical+High 차단 / 리포팅만. 11월 false positive 측정 후 택1(위 예시는 KEV 차단).

---

## 3.4 검증 (3.4)

- **로컬 dry-run**: `actionlint`로 YAML 린트, `act`(nektos/act)로 secscan 로컬 실행.
- **WebGoat 등 의도적 취약 리포**로 1라운드:
  - 백엔드를 ngrok으로 노출(런타임 호스트 미정이므로 1차는 ngrok) → secscan.yml을 fork에 배치 → PR 생성 → 코멘트 확인.
  - Phase 1 골든 픽스처 6 CWE가 실제로 summary에 잡히는지 교차 확인.

---

## 계약 테스트 — `tests/integration/github/test_action_contract.py`

Action이 의존하는 **응답 필드 스키마를 snapshot으로 고정**(Phase 1에서 보류했던 것).
백엔드 리팩터가 필드명을 바꾸면 Action보다 먼저 테스트가 깨지게 한다.

검증 대상(필드 존재 + 타입):
- POST 202 → `id`(uuid 문자열), `status`
- `/status` → `status`, `current_step`, `completed_steps`, `total_steps`, `vulnerability_count`, **`vulnerabilities` 부재**
- `/{id}` → `summary`에 6키(`critical/high/medium/low/info/kev_count`) 전부 존재
- 기존 `test_pipelines_api.py` 패턴(AsyncMock + dependency_overrides) 재사용.

---

## 시크릿/설정 요약

| 리포 | 시크릿 | 용도 |
|---|---|---|
| 이 리포 | `DOCKERHUB_USERNAME` | DockerHub 로그인 |
| 이 리포 | `DOCKERHUB_TOKEN` | DockerHub Read/Write 액세스 토큰 |
| 대상 리포 | `SECSCAN_BACKEND_URL` | 백엔드 베이스 URL (ngrok/영구) |
| 대상 리포 | `SECSCAN_API_KEY` | 백엔드 `settings.API_KEY`와 동일 값 |
| 대상 리포 | `SECSCAN_ENFORCE` (변수, 선택) | `true`면 차단 정책 활성화. 미설정/그 외 = 리포팅 모드 |

---

## 구현 순서 (체크리스트)

1. [x] 계약 테스트 `test_action_contract.py` 작성 (TDD — 인터페이스 고정) — **7건 통과**
2. [x] `docker-publish.yml` 작성 → `.github/workflows/docker-publish.yml`. *시크릿 등록·publish 확인은 환경 작업(아래)*
3. [ ] 백엔드 ngrok 노출 + `API_KEY` 설정 (1차 런타임) — **환경 작업**
4. [x] `secscan.yml` 작성 (trigger → poll → comment) → `docs/templates/secscan.yml`(대상 리포 복사용). `act` dry-run은 환경 작업
5. [ ] WebGoat fork에 배치 → PR로 실제 코멘트 확인 — **환경 작업**
6. [x] (보류→자리표시 완료) 차단 정책 — `SECSCAN_ENFORCE` 변수 게이트로 마련. 정책 택1은 11월 실측 후
7. [x] `actionlint`로 두 워크플로 YAML 린트 — **통과(0 errors)**, YAML 파싱 검증도 통과

### 코드 작업 완료분 (이 리포에 머지됨)
- `backend/tests/integration/github/test_action_contract.py` — 응답 스키마 snapshot 7건
- `.github/workflows/docker-publish.yml` — 이미지 build & push (활성 워크플로)
- `docs/templates/secscan.yml` — 스캔 대상 리포에 복사할 템플릿 (이 리포에서 실행되지 않게 templates/에 보관)

### 남은 환경 작업 (코드 외)
- DockerHub: `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` 시크릿 등록 → main push로 1회 publish 확인
- 백엔드 런타임: `ngrok http 8000` 노출 + `API_KEY` 설정 (URL은 무료 ngrok 특성상 매번 변동)
- 대상 리포(WebGoat fork): `secscan.yml` 복사 + `SECSCAN_BACKEND_URL`/`SECSCAN_API_KEY` 시크릿 → PR 생성해 코멘트 확인

---

## 미결정 / 리스크

- **런타임 호스트 미정** — DockerHub는 레지스트리. 실제 run 위치(ngrok→EC2/Oracle/학교 서버)는 2.5 잔여.
- **차단 정책** — §4.2, 11월 실증 후.
- **프라이빗 리포 clone** — 백엔드가 대상 리포를 clone하므로 비공개면 토큰 전달 설계 필요(현재 공개 가정).
- **ngrok URL 변동** — 무료 ngrok은 URL이 매번 바뀜 → `SECSCAN_BACKEND_URL` 갱신 필요. 영구 배포 시 해소.
- **폴링 부하** — 30초 간격은 가정. status 엔드포인트는 카운트만 하도록 이미 경량화(2.3).
