"""Arka plan orkestrasyonu: gruplama + AI analizi + Telegram bildirimi.

Gruplama (şart): Tek bir blind-SSRF/DNS denemesi birden çok resolver'dan ve
tekrarlarla saniyeler içinde 3–10 etkileşim üretir. Aynı token için kısa bir
pencere içinde gelenler tek grupta toplanır ve TEK bildirim gönderilir —
aksi halde Telegram spam olur.

AI yalnızca grubun ilk etkileşimi üzerinde çalışır; sonuç ona ait kayda yazılır
ve panele (bus) de basılır.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from nopanic import deadline

from app.models import Interaction
from app.services import ai, telegram


@dataclass
class _Group:
    first: Interaction
    count: int = 0
    timer: asyncio.Task | None = field(default=None)


class Pipeline:
    def __init__(self, storage, bus, group_window_s: float) -> None:
        self._storage = storage
        self._bus = bus
        self._window = group_window_s
        self._groups: dict[str, _Group] = {}
        self._lock = asyncio.Lock()

    async def handle(self, interaction: Interaction) -> None:
        """Her yakalanan etkileşim için (bloklamadan) çağrılır."""
        async with self._lock:
            group = self._groups.get(interaction.token)
            if group is None:
                group = _Group(first=interaction, count=1)
                group.timer = asyncio.create_task(self._flush_after(interaction.token))
                self._groups[interaction.token] = group
            else:
                group.count += 1

    async def _flush_after(self, token: str) -> None:
        try:
            await asyncio.sleep(self._window)
        except asyncio.CancelledError:
            return
        async with self._lock:
            group = self._groups.pop(token, None)
        if group is None:
            return
        await self._process(group)

    # Tüm arka plan zinciri (AI + depolama + bildirim) için uçtan uca üst sınır:
    # takılan bir adım görevi sonsuza dek açık tutmasın.
    @deadline(25.0)
    async def _process(self, group: _Group) -> None:
        report = await ai.analyze(group.first)
        group.first.ai_report = report
        await self._storage.set_ai_report(group.first.id, report)
        await self._bus.publish(
            {"type": "ai", "id": group.first.id, "token": group.first.token,
             "ai_report": report}
        )
        await telegram.notify(group.count, group.first, report)

    async def shutdown(self) -> None:
        """Bekleyen grupları iptal et (uygulama kapanışında)."""
        async with self._lock:
            groups = list(self._groups.values())
            self._groups.clear()
        for g in groups:
            if g.timer:
                g.timer.cancel()
