from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/mirae_naeil"

    # Security
    SECRET_KEY: str = "change-me-in-production"
    # CI/CD 인증용 API 키. 비어 있으면 인증 비활성화 (개발/검증 단계).
    # 값이 설정되면 보호된 엔드포인트는 X-API-Key 헤더로 이 값을 요구한다.
    API_KEY: str = ""

    # External APIs
    NVD_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""  # OpenAI API 키 (없으면 AI 분석 비활성화)

    # Pipeline workspace (where cloned repos are stored)
    WORKSPACE_DIR: str = "/tmp/mirae_naeil_workspace"

    # Semgrep
    SEMGREP_BINARY: str = "semgrep"
    SEMGREP_TIMEOUT: int = 300  # seconds


settings = Settings()
