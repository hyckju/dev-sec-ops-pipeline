from enum import Enum


class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepType(str, Enum):
    CLONE = "clone"
    INSTALL = "install"
    TEST = "test"
    SECURITY_SCAN = "security_scan"
    BUILD = "build"
    REPORT = "report"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CveField(str, Enum):
    """리포트에 포함할 CVE 정보 필드 (최대 4개 선택)."""
    CVE_ID      = "cve_id"       # CVE ID + NVD 링크
    CWE         = "cwe"          # CWE 분류 코드 + MITRE 링크
    CVSS_SCORE  = "cvss_score"   # CVSS 심각도 점수 및 버전
    KEV_LISTED  = "kev_listed"   # CISA KEV 등재 여부
    CPE_LIST    = "cpe_list"     # 영향받는 제품(CPE) 목록
    DESCRIPTION = "description"  # 취약점 설명 텍스트
