# 진행 현황 및 로드맵 (CI/CD 보안 파이프라인)

마지막 업데이트: 2026-07-19

관련 문서
- 현재 구현 명세: [`security-scan-feature.md`](./security-scan-feature.md)
- Phase별 상세 작업 일지: [`phase-1-test-foundation.md`](./phase-1-test-foundation.md) · [`phase-2-cicd-interface.md`](./phase-2-cicd-interface.md) · [`phase-3-github-actions.md`](./phase-3-github-actions.md) · [`phase-4-selective-analysis.md`](./phase-4-selective-analysis.md)
- 일정 원본: `../2026학년도 C-리빙랩 프로젝트 참여신청서 .hwpx`

---

## 1. 한 줄 요약

백엔드 보안 스캔 엔진(6단계 파이프라인 + Semgrep + NVD + AI 후처리)은 구현 완료.
Phase 1~3 완료(Phase 3은 2026-07-19 ngrok+fork PR로 라이브 검증까지 끝냄). Phase 4는 코드 완료·11월 실측 데이터만 남음.
Phase 5(SARIF)는 여유 있으면 진행하는 선택 사항.
중간보고서(산학관주도 캡스톤디자인) 제출 기한 7/31.

---

## 2. 신청서 일정 vs 실제 진척

| 월 | 계획 | 실제 상태 | 비고 |
|---|---|---|---|
| 4월 | 기업 요구사항/배포 환경 분석 | 완료 | |
| 5월 | 시스템 아키텍처 설계 | 부분 완료 | 설계 산출물(다이어그램) 보강 필요 |
| 6월 | NVD REST API 연동 + 캐싱 | 완료 | 중간보고서 작성 중 |
| 7월 | CWE 기반 분석 + 필터링 | 완료 | |
| 8월 | 5종 취약점 탐지 고도화 + 속도 최적화 | 미시작 | |
| 9월 | 중간점검 + LLM 연동 | 완료 | |
| 10월 | GitHub Actions 등 CI/CD 통합 | 완료 | 라이브 검증 완료(2026-07-19, 예정보다 일찍) |
| 11월 | 기업 테스트베드 실증 + 경진대회(11.24) | 미시작 | |
| 12월 | 최종 보완 + 결과보고서 | 미시작 | |

---

## 3. Phase 별 진행 상황

| Phase | 상태 | 남은 작업 |
|---|---|---|
| **1. 테스트 토대** | ✅ 완료 | 없음 — 골든 픽스처 6개 CWE 전부 실제 semgrep으로 탐지 확인 |
| **2. CI/CD 인터페이스** (인증·Dockerfile·status·summary) | ✅ 완료 | 없음 |
| **3. GitHub Actions 워크플로** | ✅ 완료 | 없음 — 라이브 검증 완료(2026-07-19, ngrok + fork PR에서 trigger→poll→comment 확인). DockerHub publish 확인만 별도 잔여 |
| **4. 선택적 분석 강화** (changed_files 기반 사후 필터) | ✅ 코드 완료 | 라이브 PR에서 selective 모드 실측 (11월 데이터) |
| **5. SARIF 출력** | 미착수 | 선택 사항 — 시간 되면 진행, 아니면 생략 |

현재 전체 테스트: **122 passed, 0 failed, 0 skipped** (`cd backend && .venv/Scripts/python.exe -m pytest -q`, 2026-07-19 재실행 확인).
이전에는 골든 픽스처 8건이 "semgrep login 필요"로 skip 처리되어 있었으나, 실제 원인은 semgrep이 기본적으로
`.semgrepignore`에 따라 `tests/` 하위 경로를 스캔 대상에서 제외하는 것이었다(로그인/네트워크 문제 아님).
`--x-ignore-semgrepignore-files` 플래그로 우회하도록 고쳐 실제 스캔이 돌게 만들었고, 그 과정에서 드러난
진짜 탐지 정확도 이슈 2건(CWE-798 미탐지, CWE-22/918 공유 룰팩 교차오염)도 픽스처 수정으로 해결.
자세한 경위: [`phase-1-test-foundation.md`](./phase-1-test-foundation.md).

---

## 4. 의사결정

| 항목 | 결정 |
|---|---|
| **배포 위치** (레지스트리) | DockerHub 확정 |
| **배포 위치** (런타임 호스트) | 지금은 ngrok으로 개발 검증 → 8~9월에 EC2/Oracle Cloud 등으로 영구 전환 |
| **차단 정책** | 지금은 리포팅만(차단 없음) → 11월 실증 false positive 데이터 확보 후 확정 |
| **5월 설계 산출물** | 컴포넌트 다이어그램 + "선택적 분석" 정의 + 데이터 흐름도 — 별도 문서 보강 필요 (미착수) |

---

## 5. 핵심 코드 위치

| 영역 | 파일 |
|---|---|
| 오케스트레이션 | `backend/app/services/pipeline/pipeline_runner.py` |
| 보안 스캔 스텝 | `backend/app/services/pipeline/steps/security_scan_step.py` |
| Semgrep 통합 | `backend/app/services/security/semgrep_service.py`, `backend/app/integrations/semgrep/` |
| CVE/NVD 통합 | `backend/app/services/security/cve_service.py`, `backend/app/integrations/nvd/client.py` |
| AI 후처리 | `backend/app/integrations/gemini/client.py` |
| API 라우터 | `backend/app/api/v1/pipelines.py` |
| 스키마 | `backend/app/schemas/pipeline.py` |
| DB 모델 | `backend/app/db/models/` |
| 테스트 | `backend/tests/` |
