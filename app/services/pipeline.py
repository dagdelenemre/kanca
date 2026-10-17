"""Arka plan orkestrasyonu: AI analizi + gruplu Telegram bildirimi.

Her yakalanan etkileşim KENDİ AI analizini alır (aynı payload'lar cache ile
birleşir; kota korunur). Böylece çok-protokollü bir geri aramada (DNS + LDAP +
HTTP) payload taşıyan etkileşim de analizsiz kalmaz — eski sürümde yalnızca
grubun ilk etkileşimi analiz ediliyordu.

Telegram spam'ini önlemek için gruplama KORUNUR ama yalnızca BİLDİRİM için:
aynı token'a kısa pencere içinde gelenler tek mesajda toplanır ve o mesaj
grubun EN YÜKSEK RİSKLİ analizini gösterir. Fuzzing'e karşı grup başına AI
çağrısı ai_max_per_group ile sınırlanır.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from nopanic import deadline

from app.models import Interaction
from app.services import ai, telegram

# Risk sıralaması (en yüksek riskli raporu seçmek için).
_RISK_ORDER = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1,
}


@dataclass
class _Group:
    first: Interaction
    count: int = 1
    analyzed: int = 0
    reports: list[dict] = field(default_factory=list)
    timer: asyncio.Task | None = field(default=None)


class Pipeline:
    def __init__(self, storage, bus, group_window_s: float,
                 ai_max_per_group: int = 5) -> None:
        self._storage = storage
        self._bus = bus
        self._window = group_window_s
        self._ai_cap = ai_max_per_group
        self._groups: dict[str, _Group] = {}
        self._lock = asyncio.Lock()

    async def handle(self, interaction: Interaction) -> None:
        """Her yakalanan etkileşim için (bloklamadan) çağrılır."""
        token = interaction.token
        async with self._lock:
            group = self._groups.get(token)
            if group is None:
                group = _Group(first=interaction)
                group.timer = asyncio.create_task(self._flush_after(token))
                self._groups[token] = group
            else:
                group.count += 1
            do_analyze = group.analyzed < self._ai_cap
            if do_analyze:
                group.analyzed += 1

        if do_analyze:
            await self._analyze_one(interaction)

    @deadline(25.0)
    async def _analyze_one(self, interaction: Interaction) -> None:
        report = await ai.analyze(interaction)
        interaction.ai_report = report
        await self._storage.set_ai_report(interaction.id, report)
        await self._bus.publish(
            {"type": "ai", "id": interaction.id, "token": interaction.token,
             "ai_report": report}
        )
        async with self._lock:
            group = self._groups.get(interaction.token)
            if group is not None:
                group.reports.append(report)

    async def _flush_after(self, token: str) -> None:
        try:
            await asyncio.sleep(self._window)
        except asyncio.CancelledError:
            return
        async with self._lock:
            group = self._groups.pop(token, None)
        if group is None:
            return
        report = _max_risk(group.reports)
        await telegram.notify(group.count, group.first, report)

    async def shutdown(self) -> None:
        async with self._lock:
            groups = list(self._groups.values())
            self._groups.clear()
        for g in groups:
            if g.timer:
                g.timer.cancel()


def _max_risk(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Gruptaki en yüksek riskli raporu seç (bildirimde onu göster)."""
    if not reports:
        return {"detected_type": "Analiz yok", "confidence": 0,
                "risk_level": "UNKNOWN", "indicators": [], "summary": ""}
    return max(reports, key=lambda r: _RISK_ORDER.get(r.get("risk_level", "UNKNOWN"), -1))
