# DevSecOps 백엔드 컨테이너 이미지
# DB(postgres)는 외부, DATABASE_URL 환경변수로 주입한다.
FROM python:3.11-slim

# git: clone 스텝에서 대상 리포를 받아오는 데 필요
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 의존성 레이어 캐시: requirements가 바뀌지 않으면 재설치 생략
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 (.dockerignore로 .venv/tests 등 제외)
COPY . .

# 비루트 사용자로 실행 (권장 보안 관행)
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
