"""Panel/API kimlik doğrulama.

Tek kullanıcılı: .env içindeki ADMIN_TOKEN ile korunur. Zamanlama saldırısına
karşı sabit zamanlı karşılaştırma yapılır. Token, Authorization: Bearer <token>
veya X-Admin-Token header'ı ile verilir.
"""
from __future__ import annotations

import secrets

from fastapi import Header, HTTPException

from app.config import get_settings


def require_admin(
    authorization: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
) -> None:
    settings = get_settings()
    provided = x_admin_token
    if not provided and authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:]
    if not provided or not secrets.compare_digest(provided, settings.admin_token):
        raise HTTPException(status_code=401, detail="Yetkisiz")
