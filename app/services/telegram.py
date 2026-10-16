"""Telegram bildirim servisi.

parse_mode=HTML kullanılır ve dinamik değerler html.escape() ile sarılır
(Markdown'ın _/* ayrıştırma hatalarından kaçınmak için). Ağ hataları sistemi
düşürmemeli: nopanic timeout/retry/fallback ile sarılır.
"""
from __future__ import annotations

import html
from typing import Any

import httpx
from nopanic import compose, fallback, retry, timeout

from app.config import get_settings
from app.models import Interaction

_tg_policy = compose(
    fallback(lambda exc: False, on=(Exception,)),
    retry(attempts=2),
    timeout(5.0),
)

_RISK_EMOJI = {
    "INFO": "⚪",
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
    "UNKNOWN": "⚪",
}


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _format(count: int, first: Interaction, ai: dict[str, Any]) -> str:
    risk = ai.get("risk_level", "UNKNOWN")
    emoji = _RISK_EMOJI.get(risk, "⚪")
    indicators = ", ".join(ai.get("indicators", [])) or "Yok"
    extra = f" <b>(+{count - 1} benzer)</b>" if count > 1 else ""
    return (
        f"{emoji} <b>Etkileşim yakalandı</b>{extra}\n"
        f"🏷️ <code>{_esc(first.token)}</code> · {_esc(first.protocol.value).upper()}\n"
        f"🌐 Kaynak: <code>{_esc(first.source_ip)}</code>\n"
        f"🧠 Risk: <b>{_esc(risk)}</b> · Tür: {_esc(ai.get('detected_type'))}\n"
        f"🔎 Bulgular: {_esc(indicators)}\n"
        f"📝 {_esc(ai.get('summary'))}"
    )


@_tg_policy
async def notify(count: int, first: Interaction, ai: dict[str, Any]) -> bool:
    settings = get_settings()
    if not settings.telegram_enabled:
        return False
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            url,
            json={
                "chat_id": settings.telegram_chat_id,
                "text": _format(count, first, ai),
                "parse_mode": "HTML",
            },
        )
        resp.raise_for_status()
    return True
