"""Gelen ham veriyi güvenli şekilde ayrıştırma yardımcıları.

Yakalanan veri güvenilmezdir; ayrıştırma hataları kaydı düşürmemeli,
yalnızca ham/hex veriye düşmelidir. nopanic.fallback ile sarılır.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from nopanic import fallback


@fallback(lambda exc: {"_parse_error": str(exc)}, on=(Exception,))
def parse_http_body(raw: bytes, content_type: str) -> Any:
    """İçerik tipine göre gövdeyi ayrıştırır; başarısızsa fallback döner."""
    if not raw:
        return None
    ct = (content_type or "").lower()
    if "application/json" in ct:
        return json.loads(raw.decode("utf-8"))
    if "application/x-www-form-urlencoded" in ct:
        # keep_blank_values ve çoklu değerleri koru.
        pairs = urllib.parse.parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
        return [[k, v] for k, v in pairs]
    # Diğer tiplerde güvenli metin denemesi.
    return raw.decode("utf-8", errors="replace")


def multi_items(items) -> list[list[str]]:
    """Header/query gibi tekrar eden anahtarları kaybetmeden liste yapar."""
    return [[k, v] for k, v in items]
