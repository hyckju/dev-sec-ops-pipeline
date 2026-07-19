"""CWE-798: Use of Hard-coded Credentials — 의도적 취약 픽스처.

p/secrets 룰팩(270개 룰) 중 218개는 Semgrep Pro 전용이라 무료 티어로는
발동하지 않는다. 무료 티어에서 실제로 발동하는 건:
- `python.boto3.security.hardcoded-token` — boto3.client()에 자격증명을
  키워드 인자로 직접 넘기는 패턴 (아래 connect_s3 참고)

나머지 상수(AWS access key 등)는 교육용으로 남겨두되, 실제 탐지를 보장하는
건 아래 boto3.client() 호출 하나다.

주의: 진짜 서비스 prefix를 가진 secret(`sk_live_*`, Slack webhook URL 등)은
GitHub push protection이 차단하므로 사용 금지. AWS 예제 값은 AWS 공식
문서의 example 값이라 GitHub allowlisted.
"""

import boto3

# ruleid: aws-secret-access-key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def connect_s3():
    # ruleid: hardcoded-token — boto3.client()에 자격증명 직접 전달
    return boto3.client(
        "s3",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

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
