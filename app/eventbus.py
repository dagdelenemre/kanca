"""Process içi async olay otobüsü (fan-out).

Redis Pub/Sub yerine tek kullanıcılı/tek process dağıtımda canlı yayın için
kullanılır. Her SSE abonesi bir asyncio.Queue alır; yeni etkileşimler tüm
abonelere dağıtılır. Abone yavaşsa kuyruğu dolar ve o abone için en eski olay
düşürülür (yayın tüm sistemi bloklamaz).
"""
from __future__ import annotations

import asyncio
from typing import Any


class EventBus:
    def __init__(self, max_queue: int = 1000) -> None:
        self._subscribers: set[asyncio.Queue[Any]] = set()
        self._max_queue = max_queue
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[Any]:
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize=self._max_queue)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[Any]) -> None:
        async with self._lock:
            self._subscribers.discard(q)

    async def publish(self, event: Any) -> None:
        async with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Yavaş abone: en eskiyi at, yenisini koy.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass
