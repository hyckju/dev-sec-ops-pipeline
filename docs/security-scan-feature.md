# 미래내일 DevSecOps 보안 스캔 기능 기술 문서 (현재 구현 기준)

## 1. 개요

현재 시스템은 GitHub 저장소를 대상으로 아래 흐름을 자동 수행한다.

- 코드 클론
- 의존성 설치
- 테스트 실행
- 보안 스캔 (CWE 선택형)
- 빌드 실행
- 리포트 생성

보안 스캔은 **CWE 기반 Semgrep 탐지 + NVD CVE 매핑 + Claude AI 후처리 권고**를 결합한 구조다.

---

## 2. 현재 파이프라인 구조

```text
clone → install → test → security_scan → build → report
```

- `install`, `test` 실패 시에도 보안 스캔은 계속 진행
- `clone`/`security_scan`/`build` 실패 시 파이프라인 실패 처리

핵심 오케스트레이션: `backend/app/services/pipeline/pipeline_runner.py`

---

## 3. 보안 스캔 핵심 동작

핵심 구현: `backend/app/services/pipeline/steps/security_scan_step.py`

선택된 CWE를 순차 처리하며, CWE 1개 단위로 아래를 실행한다.

1. **NVD API 조회**
   - `cve_service.fetch_cves_by_cwe([cwe_id])`
2. **Semgrep 스캔**
   - 해당 CWE 룰만 실행
3. **AI 후처리 권고 생성**
   - Semgrep이 탐지한 취약점 목록을 Claude가 다시 검토
   - 코드 스니펫과 탐지 맥락을 바탕으로 수정 권고를 생성
   - AI는 공식 취약점 수를 늘리지 않고, 기존 탐지 결과를 설명/보완하는 역할만 수행
4. **CVE 캐시 저장/KEV 업데이트**
   - 루프 종료 후 일괄 저장

---

## 4. 스캔 대상 CWE (현재 설정)

설정 위치: `backend/app/services/security/semgrep_service.py` (`CWE_SCAN_CONFIG`)

| CWE ID | 라벨 | 룰 |
|---|---|---|
| CWE-89 | SQL Injection | `p/sql-injection` |
| CWE-79 | Cross-Site Scripting (XSS) | `p/xss` |
| CWE-22 | Path Traversal | `p/java` + 키워드 필터 |
| CWE-918 | Server-Side Request Forgery (SSRF) | `p/java` + 키워드 필터 |
| CWE-78 | Command Injection | `p/command-injection` |
| CWE-798 | Hardcoded API Key / Credentials | `p/secrets` |

---

## 5. CVE 연동 방식

현재 구조는 **CWE 기반 탐지 + CVE 데이터 결합 + AI 후처리**이다.

- 공식 탐지: Semgrep
- AI 역할: 후처리 및 권고 생성
- CVE 정보: NVD API로 CWE별 조회 후 finding에 매핑

매핑 결과에 포함되는 대표 정보:

- `cve_id`
- `cvss_score`, `cvss_version`
- `cve_description`
- (캐시 DB 기준) `kev_listed`, `cpe_list`

---

## 6. 리포트 출력 구조 (현재)

리포트 생성: `backend/app/services/pipeline/steps/report_step.py`

### 6.1 CWE Coverage

- 컬럼: `CWE | Vulnerability | Status | NVD+Semgrep+AI`
- `Status`는 공식 탐지 수를 표시
   - `x finding(s)` 또는 `Not detected`
- 시간 `[Xs]`는 **해당 CWE의 NVD+Semgrep+AI 총 시간**

### 6.2 Total 시간

- `sum(round(cwe_scan_times[cwe]))`로 계산
- 표시 문구: `(NVD API + semgrep + AI 후처리)`

### 6.3 Vulnerability Summary

- 심각도 합계(Critical/High/Medium/Low/Info)
- AI는 상세 항목의 권고사항 생성에 사용됨

### 6.4 Vulnerability Details

각 항목에 대해 다음을 출력한다.

- Severity, Title
- Location, Rule ID
- CWE, MITRE 링크
- CVSS/CVE/NVD 링크 (필드 선택 시)
- 상세 설명
- 권고사항(Claude 후처리 결과)

---

## 7. 데이터 저장 구조 (현재 코드 기준)

### 7.1 vulnerabilities

모델: `backend/app/db/models/vulnerability.py`

주요 컬럼:

- `pipeline_id`
- `cve_id`
- `severity`
- `title`
- `description`
- `file_path`
- `line_number`
- `rule_id`
- `raw_output`

주의:
- `suggestion`은 리포트 생성에 사용될 수 있지만 DB 컬럼으로 별도 저장하지 않는다.

### 7.2 cve_catalog

모델: `backend/app/db/models/cve_catalog.py`

주요 컬럼:

- `cve_id` (unique)
- `cwe_id`
- `cvss_score`, `cvss_version`
- `severity`
- `description`
- `published`
- `kev_listed`
- `cpe_list`

---

## 8. 환경 변수

| 변수명 | 설명 |
|---|---|
| `DATABASE_URL` | PostgreSQL 연결 문자열 |
| `NVD_API_KEY` | NVD API 키 (선택) |
| `ANTHROPIC_API_KEY` | Claude API 키 |
| `SEMGREP_BINARY` | Semgrep 바이너리 경로 |
| `SEMGREP_TIMEOUT` | Semgrep timeout(초) |

---

## 9. API 엔드포인트

- `POST /api/v1/pipelines/` : 파이프라인 생성/실행
- `GET /api/v1/pipelines/` : 목록 조회
- `GET /api/v1/pipelines/{id}` : 상세 조회
- `GET /health` : 헬스체크

예시 요청:

```json
{
  "github_url": "https://github.com/WebGoat/WebGoat",
  "selected_cwe_ids": ["CWE-89", "CWE-79", "CWE-22"],
  "selected_cve_fields": ["cve_id", "cwe", "cvss_score", "description"]
}
```

---

## 10. 타이밍 해석 가이드

- CWE별 `[Xs]`: 해당 CWE의 `NVD 조회 + Semgrep + AI 후처리 권고` 포함
- `Total`: CWE별 표시값 합계 기준(반올림 합)
- 콘솔 footer `Xs total`: clone~report 전체 파이프라인 실시간

즉, `footer total`은 clone/install/test 오버헤드를 포함하므로 Coverage `Total`보다 클 수 있다.
build가 수행된 경우 build 시간도 footer total에 포함된다.

---

## 11. 운영 시 주의사항

- AI는 공식 취약점 수를 변경하지 않으며, Semgrep 탐지 결과에 대한 수정 권고를 보조한다.
- 공식 취약점 수/심각도 집계/DB 저장은 Semgrep 결과 기준이다.

---

## 12. 실행 방법

```bash
cd backend
uvicorn app.main:app --reload --reload-dir app
```

마이그레이션:

```bash
alembic upgrade head
```
