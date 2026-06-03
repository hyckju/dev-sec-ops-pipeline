"""verify_api_key 의존성 단위 테스트.

설계 계약: settings.API_KEY가 비어 있으면 인증을 건너뛰고(개발/ngrok/테스트),
값이 설정된 경우에만 X-API-Key 헤더 일치를 강제한다.
함수를 직접 호출해 ASGI/라우팅 없이 분기만 검증한다.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.deps import verify_api_key
from app.core.config import settings


# ── API_KEY 미설정 → 통과 (인증 비활성화) ──────────────────────────────


async def test_passes_when_key_unset_and_header_absent(monkeypatch):
    """API_KEY가 비어 있으면 헤더가 없어도 예외 없이 통과해야 한다."""
    monkeypatch.setattr(settings, "API_KEY", "")
    assert await verify_api_key(x_api_key=None) is None


async def test_passes_when_key_unset_even_with_header(monkeypatch):
    """API_KEY가 비어 있으면 헤더 값이 무엇이든 무시하고 통과해야 한다."""
    monkeypatch.setattr(settings, "API_KEY", "")
    assert await verify_api_key(x_api_key="anything") is None


# ── API_KEY 설정 → 헤더 검증 강제 ──────────────────────────────────────


async def test_rejects_missing_header_when_key_set(monkeypatch):
    """API_KEY 설정 + 헤더 누락 → 401."""
    monkeypatch.setattr(settings, "API_KEY", "secret-key")
    with pytest.raises(HTTPException) as exc:
        await verify_api_key(x_api_key=None)
    assert exc.value.status_code == 401


async def test_rejects_mismatched_header_when_key_set(monkeypatch):
    """API_KEY 설정 + 헤더 불일치 → 401."""
    monkeypatch.setattr(settings, "API_KEY", "secret-key")
    with pytest.raises(HTTPException) as exc:
        await verify_api_key(x_api_key="wrong-key")
    assert exc.value.status_code == 401


async def test_passes_when_header_matches_key(monkeypatch):
    """API_KEY 설정 + 헤더 일치 → 통과."""
    monkeypatch.setattr(settings, "API_KEY", "secret-key")
    assert await verify_api_key(x_api_key="secret-key") is None
