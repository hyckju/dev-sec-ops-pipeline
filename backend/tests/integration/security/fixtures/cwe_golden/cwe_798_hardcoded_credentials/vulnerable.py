"""CWE-798: Use of Hard-coded Credentials — 의도적 취약 픽스처.

p/secrets 룰팩 탐지 대상:
- AWS access key (AWS 공식 예제 값 — GitHub allowlisted)
- GitHub PAT 패턴 (의도적 길이 불일치로 GitHub push-protection 회피)
- 평문 패스워드 / API key / JWT secret 상수 (generic-api-key 룰)

주의: 진짜 서비스 prefix를 가진 secret(`sk_live_*`, Slack webhook URL 등)은
GitHub push protection이 차단하므로 사용 금지. semgrep의 generic-api-key
룰은 변수명 + 문자열 리터럴 조합만으로도 발동한다.
"""

# ruleid: aws-secret-access-key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ruleid: github-token (길이 의도적 단축 — GitHub scanner 회피)
GITHUB_TOKEN_LIKE = "ghp_AAAAAAAAAAAAAAAAAAAA"

# ruleid: generic-api-key — service prefix 없이 변수명만으로 발동
PAYMENT_GATEWAY_API_KEY = "hardcoded-payment-gateway-key-do-not-commit"
THIRD_PARTY_API_TOKEN = "static-third-party-bearer-token-abcdefg-12345"
INTERNAL_WEBHOOK_SECRET = "shared-secret-for-internal-webhook-signing-xyz"


def connect_database():
    # ruleid: hardcoded-password
    db_password = "super-secret-password-123"
    db_user = "admin"
    return (db_user, db_password)


class Config:
    # ruleid: hardcoded-password / generic-api-key
    SECRET_KEY = "my-very-secret-flask-key-do-not-share-12345"
    JWT_SECRET = "another-hardcoded-jwt-signing-key-67890"
    ENCRYPTION_KEY = "hardcoded-aes-256-key-must-not-be-in-source"
