"""
HWP COM 자동화로 중간보고서를 작성하는 스크립트.
Hancom Word 2020 이상 설치 필요.
"""
import win32com.client
import win32clipboard
import time
import os

TEMPLATE_PATH = os.path.abspath(
    "[서식5] 산학관주도 캡스톤디자인 중간보고서.hwp"
)
SAVE_PATH = os.path.abspath(
    "[수호당팀] 산학관주도 캡스톤디자인 중간보고서_2026.hwp"
)

# ─── 보고서 내용 ──────────────────────────────────────────────────────────────

PROGRESS_PCT = "55%"

PROGRESS_CONTENT = (
    "▶ Phase 1 — 테스트 토대  완료 (2026-05월)\r\n"
    "  백엔드 보안 스캔 엔진 구현: 파이프라인 6단계(clone → install → test → security_scan → build → report)\r\n"
    "  보안 스캔 구성: Semgrep CWE 탐지 + NVD REST API 실시간 CVE 매핑 + Claude AI 수정 권고\r\n"
    "  탐지 CWE 6종: SQL Injection(89) / XSS(79) / Path Traversal(22) / SSRF(918) / Command Injection(78) / 하드코딩 자격증명(798)\r\n"
    "  자동화 테스트 4계층 수립: 단위 · 통합 · 계약 · 골든 데이터셋 (83 passed + 8 skipped)\r\n\r\n"
    "▶ Phase 2 — CI/CD 인터페이스  완료 (2026-06-01)\r\n"
    "  API 키 인증(Bearer 토큰, 미설정 시 비활성), Dockerfile 및 .dockerignore 작성\r\n"
    "  경량 상태 폴링 엔드포인트 추가: GET /api/v1/pipelines/{id}/status\r\n"
    "  PR 코멘트용 summary 필드 추가: critical/high/medium/low/info/kev_count\r\n"
    "  이미지 레지스트리 DockerHub 확정 / 신규 테스트 11건 추가 (94 passed + 8 skipped)\r\n\r\n"
    "▶ Phase 3 — GitHub Actions 워크플로  코드 완료 (2026-06-02)\r\n"
    "  docker-publish.yml: main 브랜치 푸시 시 DockerHub 이미지 자동 빌드 · 푸시\r\n"
    "  secscan.yml: PR 트리거 → 백엔드 파이프라인 호출 → 폴링 → PR 코멘트 자동 회신 (재사용 템플릿)\r\n"
    "  SECSCAN_ENFORCE 변수 게이트(차단 정책 on/off), actionlint 0 errors 달성\r\n"
    "  GitHub Action 계약 테스트 7건 추가 (101 passed + 8 skipped)\r\n\r\n"
    "▶ Phase 4 — 선택적 분석 강화  코드 완료 (2026-06-10) [신청서 핵심 차별점]\r\n"
    "  PR diff(git diff --name-only) 결과를 changed_files로 전달, 변경 파일에 해당하는 finding만 추출\r\n"
    "  사후 필터 방식 채택: Semgrep은 전체 스캔 → finding을 변경 집합과 매칭(AI 호출 최소화)\r\n"
    "  scan_mode(selective/full) 자동 전환 및 비교 로깅 내장(11월 실측 데이터 수집용)\r\n"
    "  SECSCAN_SELECTIVE 게이트(미설정 시 기존 전수 스캔, 하위호환 보장)\r\n"
    "  신규 테스트 11건 추가 (전체 112 passed + 8 skipped)\r\n\r\n"
    "※ Phase 3 · 4 잔여 환경 작업: DockerHub 시크릿 등록, ngrok 백엔드 노출, 대상 리포 PR 라이브 검증 — 7~8월 예정"
)

ACHIEVEMENTS = (
    "  [핵심 차별점] 선택적 분석(Selective Analysis) 구현 완료\r\n"
    "  - PR diff 기반 사후 필터: 변경된 파일에 해당하는 취약점 finding만 추출\r\n"
    "  - AI(Claude) 호출을 변경 파일 범위로 제한하여 분석 비용 및 시간 절감\r\n"
    "  - scan_mode 비교 로깅으로 selective vs. full 스캔 효율 데이터 자동 수집\r\n\r\n"
    "  6종 CWE 동시 탐지 + NVD 실시간 CVE 연동 + Claude AI 수정 권고 통합 파이프라인 완성\r\n\r\n"
    "  GitHub Actions 재사용 가능 워크플로 템플릿 설계 (복수 리포지터리 1파일 배포)\r\n\r\n"
    "  자동화 테스트 112건 수립 (단위 / 통합 / 계약 / 골든 데이터셋 4계층 구조)\r\n\r\n"
    "  클라우드에어 JIRA 프리미엄 활용 프로젝트 협업 도구 구성"
)

JULY_REPLACE_FIND    = "OO 작품 제작을 위한 OO 재료 구매"
JULY_REPLACE_CONTENT = "Phase 4 완료 main 머지, Phase 5(SARIF 출력) 설계 착수"

SCHEDULE_AFTER_JULY = [
    # (skip 여부, 내용)  — 순서대로 7월 다음 행부터
    (False, "Phase 5 SARIF v2.1.0 출력 구현, 취약점 탐지 고도화, 스캔 속도 최적화 시작"),  # 8월
    (False, "중간점검, 백엔드 영구 배포 전환(ngrok -> 클라우드 서버), LLM 연동 고도화"),    # 9월
    (False, "GitHub Actions 라이브 검증(WebGoat fork + 실제 PR), 클라우드에어 테스트베드 환경 구성"),  # 10월
    (True,  ""),   # 11월 — 이미 '경진대회 참가(11/24 예정)' 기입됨, 건너뜀
    (False, "최종 보완 및 버그 수정, 결과보고서 작성 및 제출"),  # 12월
]

COMPLETION_DATE = "2026-12-31"


# ─── COM 헬퍼 ─────────────────────────────────────────────────────────────────

def clipboard_put(text: str):
    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32clipboard.CF_UNICODETEXT, text)
    finally:
        win32clipboard.CloseClipboard()


def find_replace(hwp, find_str: str, replace_str: str) -> bool:
    act = hwp.CreateAction("FindReplace")
    pset = act.CreateSet()
    act.GetDefault(pset)
    pset.SetItem("FindString", find_str)
    pset.SetItem("ReplaceString", replace_str)
    pset.SetItem("IgnoreMessage", 1)
    pset.SetItem("FindAll", 1)
    return bool(act.Execute(pset))


def find_text(hwp, search: str) -> bool:
    hwp.HAction.Run("MoveDocBegin")
    act = hwp.CreateAction("Find")
    pset = act.CreateSet()
    act.GetDefault(pset)
    pset.SetItem("FindString", search)
    pset.SetItem("IgnoreMessage", 1)
    pset.SetItem("Direction", 0)
    return bool(act.Execute(pset))


def insert_via_clipboard(hwp, text: str):
    clipboard_put(text)
    time.sleep(0.1)
    hwp.HAction.Run("Paste")


def nav_and_fill(hwp, anchor: str, content: str, cells_right: int = 1) -> bool:
    if not find_text(hwp, anchor):
        print(f"  [WARN] 앵커 '{anchor}' 를 찾지 못했습니다.")
        return False
    for _ in range(cells_right):
        hwp.HAction.Run("TableRightCell")
    # 셀 내 전체 선택 후 붙여넣기
    hwp.HAction.Run("SelectAll")
    insert_via_clipboard(hwp, content)
    time.sleep(0.2)
    return True


# ─── 메인 ────────────────────────────────────────────────────────────────────

def main():
    print("HWP COM 연결 중...")
    hwp = win32com.client.gencache.EnsureDispatch("HWPFrame.HwpObject")
    try:
        hwp.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule")
    except Exception:
        pass
    hwp.XHwpWindows.Item(0).Visible = True

    print(f"템플릿 열기: {TEMPLATE_PATH}")
    hwp.Open(TEMPLATE_PATH, "HWP", "forceopen:true")
    time.sleep(2)

    # 1. 진행률
    print("1. 현재 프로젝트 진행률 입력...")
    nav_and_fill(hwp, "현재 프로젝트 진행률(%)", PROGRESS_PCT)

    # 2. 프로젝트 진행내용
    print("2. 프로젝트 진행내용 입력...")
    nav_and_fill(hwp, "프로젝트 진행내용", PROGRESS_CONTENT)

    # 3. 우수 성과
    print("3. 프로젝트 우수 성과 입력...")
    nav_and_fill(hwp, "프로젝트 우수 성과", ACHIEVEMENTS)

    # 4. 7월 일정 플레이스홀더 교체
    print("4. 7월 일정 플레이스홀더 교체...")
    ok = find_replace(hwp, JULY_REPLACE_FIND, JULY_REPLACE_CONTENT)
    print(f"   FindReplace 결과: {'성공' if ok else '미발견'}")

    # 5. 8~12월 일정 — 7월 내용 셀에서 TableLowerCell로 순차 이동
    print("5. 8~12월 일정 순차 입력...")
    if find_text(hwp, JULY_REPLACE_CONTENT):
        print("   7월 내용 셀 찾음 → 이하 행 순차 이동")
        for month_idx, (skip, content) in enumerate(SCHEDULE_AFTER_JULY, start=8):
            hwp.HAction.Run("TableLowerCell")
            if skip:
                print(f"   {month_idx}월: 건너뜀 (기존 내용 유지)")
                continue
            hwp.HAction.Run("SelectAll")
            insert_via_clipboard(hwp, content)
            print(f"   {month_idx}월: 입력 완료")
            time.sleep(0.2)
    else:
        print("  [WARN] 7월 내용 셀을 찾지 못했습니다 — 8~12월 수동 입력 필요")

    # 6. 예상완료일
    print("6. 프로젝트 진행 예상완료일 입력...")
    nav_and_fill(hwp, "프로젝트 진행 예상완료일", COMPLETION_DATE)

    # 저장
    print(f"\n저장 중: {SAVE_PATH}")
    hwp.SaveAs(SAVE_PATH, "HWP", "")
    print("완료!")


if __name__ == "__main__":
    main()
