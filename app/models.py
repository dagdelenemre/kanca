"""Çekirdek veri modelleri.

Mimarinin kalbi: hangi protokolden gelirse gelsin her etkileşim tek bir
Interaction kaydına indirgenir ve bir token (kanca) ile ilişkilendirilir.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_serializer


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


class Protocol(str, Enum):
    HTTP = "http"
    DNS = "dns"
    SMTP = "smtp"   # v2 sonrası
    LDAP = "ldap"   # v2 sonrası


class MockConfig(BaseModel):
    """Bir kancanın HTTP yakalama uçlarına vereceği yanıt kuralı."""
    status_code: int = Field(default=200, ge=100, le=599)
    headers: dict[str, str] = Field(
        default_factory=lambda: {"Content-Type": "application/json"}
    )
    body: str = '{"status": "captured"}'
    delay_ms: int = Field(default=0, ge=0, le=10_000)


class Hook(BaseModel):
    """Kullanıcının oluşturduğu yakalama kancası."""
    token: str = Field(default_factory=_new_id)
    label: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    mock_config: MockConfig = Field(default_factory=MockConfig)
    notify: bool = True


class Interaction(BaseModel):
    """Tek bir yakalanmış etkileşim (protokolden bağımsız)."""
    id: str = Field(default_factory=_new_id)
    token: str
    protocol: Protocol
    timestamp: datetime = Field(default_factory=_utcnow)
    source_ip: str = "unknown"
    source_host: Optional[str] = None
    # Ham etkileşim; storage katmanında base64 olarak saklanır.
    raw: bytes = b""
    # Protokole göre ayrıştırılmış özet. Tekrar eden HTTP header/query
    # değerleri kaybedilmeden (liste olarak) tutulur.
    parsed: dict[str, Any] = Field(default_factory=dict)
    size_bytes: int = 0
    ai_report: Optional[dict[str, Any]] = None
    group_id: Optional[str] = None

    @field_serializer("raw", when_used="json")
    def _ser_raw(self, v: bytes) -> str:
        # Ham veri ikili olabilir (DNS paketi vb.); JSON'a base64 olarak çıkar
        # ki UTF-8 çözümleme patlamasın.
        return base64.b64encode(v).decode("ascii")
