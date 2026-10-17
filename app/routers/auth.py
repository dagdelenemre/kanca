"""Panel/API kimlik doğrulama.

Tek kullanıcılı: .env içindeki ADMIN_TOKEN ile korunur. Zamanlama saldırısına
karşı sabit zamanlı karşılaştırma yapılır.

İki yol kabul edilir:
- Header (curl/API): `Authorization: Bearer <token>` veya `X-Admin-Token`.
- Cookie (tarayıcı/SSE): `POST /api/login` ile kurulan `kanca_sid` oturum
  çerezi. Böylece admin token URL'de (ör. SSE ?token=) taşınmaz ve erişim
  loglarına düşmez.
"""
from __future__ import annotations

import secrets
import time

from fastapi import Cookie, Header, HTTPException

from app.config import get_settings

COOKIE_NAME = "kanca_sid"
_SESSION_TTL = 7 * 24 * 3600  # 7 gün

# Geçerli oturum id'leri -> oluşturma zamanı (bellek içi; tek process).
_sessions: dict[str, float] = {}


def _token_ok(provided: str | None) -> bool:
    settings = get_settings()
    return bool(provided) and secrets.compare_digest(provided, settings.admin_token)


def create_session() -> str:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = time.time()
    return sid


def destroy_session(sid: str | None) -> None:
    if sid:
        _sessions.pop(sid, None)


def _session_ok(sid: str | None) -> bool:
    if not sid:
        return False
    ts = _sessions.get(sid)
    if ts is None:
        return False
    if time.time() - ts > _SESSION_TTL:
        _sessions.pop(sid, None)
        return False
    return True


def require_admin(
    authorization: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    kanca_sid: str | None = Cookie(default=None),
) -> None:
    provided = x_admin_token
    if not provided and authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:]
    if _token_ok(provided) or _session_ok(kanca_sid):
        return
    raise HTTPException(status_code=401, detail="Yetkisiz")
