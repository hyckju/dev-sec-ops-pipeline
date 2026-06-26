# 시스템 아키텍처 설계서

**작품명**: 실시간 CVE 취약점 반영 및 선택적 분석을 통한 효율적인 CI/CD 보안 파이프라인 아키텍처  
**팀명**: 수호당  
**작성일**: 2026-05 (설계) / 2026-06 문서화  

---

## 1. 시스템 개요

개발자가 코드 변경(PR)을 GitHub에 올리는 순간, 자동으로 보안 취약점을 검사하고 그 결과를 PR 화면에 코멘트로 회신하는 CI/CD 보안 자동화 시스템이다.

핵심 차별점은 두 가지다.

1. **실시간 CVE 연동**: 미국 국가 취약점 데이터베이스(NVD)에서 최신 취약점 정보를 실시간으로 가져와 검사 결과에 반영한다.  
2. **선택적 분석(Selective Analysis)**: 전체 코드가 아닌 이번 PR에서 변경된 파일만 선별하여 검사한다. 검사 시간과 불필요한 알림을 줄이는 핵심 설계 결정이다.

---

## 2. 시스템 구성도

```
┌─────────────────────────────────────────────────────────────────┐
│                     외부 CI/CD 환경                              │
│                                                                 │
│   개발자 코드 Push/PR                                            │
│        │                                                        │
│        ▼                                                        │
│   GitHub Actions (secscan.yml)                                  │
│   - PR diff 추출 (변경 파일 목록)                                │
│   - 백엔드 API 호출 (POST /api/v1/pipelines/)                   │
│   - 결과 폴링 (GET /api/v1/pipelines/{id}/status)               │
│   - PR 코멘트 자동 작성                                          │
└───────────────────────┬─────────────────────────────────────────┘
                        │  HTTPS + API Key 인증
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     백엔드 서버 (FastAPI)                        │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────────────────────────┐   │
│  │  API Layer  │    │         Pipeline Runner               │   │
│  │             │    │                                      │   │
│  │ POST /pipelines  │  1단계: Clone (저장소 다운로드)       │   │
│  │ GET  /status│───▶│  2단계: Install (의존성 설치)         │   │
│  │ GET  /{id}  │    │  3단계: Test (테스트 실행)            │   │
│  │ GET  /sarif │    │  4단계: Security Scan ★              │   │
│  └─────────────┘    │  5단계: Build (빌드)                  │   │
│                     │  6단계: Report (결과 리포트 생성)      │   │
│                     └──────────────┬───────────────────────┘   │
│                                    │                            │
│              ┌─────────────────────┼──────────────────┐        │
│              ▼                     ▼                   ▼        │
│   ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│   │   Semgrep (SAST) │  │  NVD REST API    │  │ Claude AI  │  │
│   │                  │  │                  │  │            │  │
│   │ CWE 룰 기반      │  │ CVE 실시간 조회  │  │ 수정 방법  │  │
│   │ 정적 코드 분석   │  │ CVSS 점수 매핑   │  │ 자동 권고  │  │
│   │ 5종 취약점 탐지  │  │ CISA KEV 연동    │  │            │  │
│   └──────────────────┘  └──────────────────┘  └────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  PostgreSQL DB                           │  │
│  │  Pipeline · Vulnerability · CVECatalog · Project · Report│  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 데이터 흐름 (PR 이벤트 → 결과 회신)

```
① 개발자가 GitHub에 Pull Request(PR) 생성
        │
② GitHub Actions 워크플로 자동 트리거
   - git diff --name-only 로 변경된 파일 목록 추출
   - 백엔드 API에 파이프라인 실행 요청
     POST /api/v1/pipelines/
     { repo_url, changed_files: ["src/auth.py", ...] }
        │
③ 백엔드: 파이프라인 6단계 순차 실행
   │
   ├── [1] Clone: 저장소를 임시 작업 공간에 다운로드
   ├── [2] Install: 프로젝트 의존성 설치
   ├── [3] Test: 기존 테스트 스위트 실행
   │
   ├── [4] Security Scan ★ (핵심 단계)
   │     │
   │     ├── NVD API: CWE별 최신 CVE 목록 조회 + 로컬 캐싱
   │     │
   │     ├── Semgrep: CWE 룰로 전체 코드 정적 분석
   │     │     └── 결과: finding(취약점 후보) 목록
   │     │
   │     ├── [선택적 분석] changed_files와 finding 매칭
   │     │     변경된 파일의 finding만 남기고 나머지 제거
   │     │     → scan_mode=selective / findings 비율 기록
   │     │
   │     ├── CVE 정보 매핑: CVSS 점수 → 심각도(critical/high/medium/low)
   │     └── Claude AI: 각 취약점에 대한 수정 권고 생성
   │
   ├── [5] Build: 프로젝트 빌드 실행
   └── [6] Report: 결과 리포트 생성 + DB 저장
        │
④ GitHub Actions: 상태 폴링
   GET /api/v1/pipelines/{id}/status  (2초마다, 최대 10분)
        │
⑤ 검사 완료 시 PR 코멘트 자동 작성
   ┌─────────────────────────────────────┐
   │ 🔒 보안 검사 결과                   │
   │ critical: 1  high: 3  medium: 5    │
   │ [상세 취약점 목록 및 수정 권고]      │
   └─────────────────────────────────────┘
```

---

## 4. 선택적 분석(Selective Analysis) 설계 결정

### 배경

기존 보안 도구는 PR이 올라올 때마다 전체 코드를 다시 검사한다.  
파일이 수천 개인 대형 프로젝트에서는 검사 시간이 수십 분에 달해 배포 병목이 발생한다.

### 채택 방식: **사후 필터(Post-filter)**

```
전체 코드 Semgrep 스캔 실행
        │
        ▼
finding 목록 (전체 파일 기준)
        │
        ▼
changed_files와 file_path 매칭
        │
        ├── 매칭 O → 결과에 포함
        └── 매칭 X → 제거 (이번 PR과 무관한 취약점)
```

**사후 필터를 선택한 이유**:
- Semgrep은 파일 단위 지정 스캔이 가능하나, 룰 캐시 효율과 cross-file 분석은 전체 스캔이 유리하다.
- AI(Claude) 호출 비용이 높으므로, 필터 이후의 finding에만 AI를 적용하여 비용을 줄인다.
- 변경 파일이 0개(빈 목록)이면 자동으로 전수 스캔으로 전환 — 하위 호환 보장.

### 측정 데이터 자동 수집

11월 기업 테스트베드 실증에서 성능을 측정하기 위해, 매 스캔마다 아래 데이터를 자동 기록한다.

| 항목 | 설명 |
|---|---|
| `scan_mode` | `selective` 또는 `full` |
| `findings_before_filter` | 필터 전 finding 총 수 |
| `findings_after_filter` | 최종 보고 finding 수 |
| `elapsed` | CWE별 소요 시간 |

---

## 5. 탐지 취약점 유형 (5종 CWE)

| # | CWE | 취약점 유형 | Semgrep 룰팩 |
|---|---|---|---|
| 1 | CWE-89  | SQL Injection | p/sql-injection |
| 2 | CWE-79  | Cross-Site Scripting (XSS) | p/xss |
| 3 | CWE-22  | 경로 조작 (Path Traversal) | p/java |
| 4 | CWE-918 | 서버 요청 위조 (SSRF) | p/java |
| 5 | CWE-78  | 명령어 인젝션 (Command Injection) | p/command-injection |

> 하드코딩 자격증명(CWE-798) 탐지는 추가 구현된 항목으로, 향후 공식 포함 예정.

---

## 6. 기술 스택

| 구분 | 기술 |
|---|---|
| 백엔드 프레임워크 | Python 3.12 + FastAPI |
| 데이터베이스 | PostgreSQL 16 (asyncpg / SQLAlchemy async) |
| 정적 분석 엔진 | Semgrep (오픈소스 SAST) |
| 취약점 데이터베이스 | NIST NVD REST API v2.0 |
| AI 후처리 | Claude (Anthropic) |
| 컨테이너화 | Docker + DockerHub 레지스트리 |
| CI/CD 통합 | GitHub Actions |
| 프로젝트 관리 | JIRA Premium (클라우드에어 제공) |
