"""Uygulama girişi: host'a göre ayrılmış panel + yakalama + DNS dinleyici.

Güvenlik açısından kritik ayrım (Host tabanlı yönlendirme):
  * panel_domain  → panel_app (auth'lu /api ve arayüz)
  * diğer tüm host'lar (base_domain alt alanları) → capture_app (yakalama)

Böylece bir saldırgan {token}.oob.../api/hooks adresine gitse bile panel API'si
O host'ta HİÇ kayıtlı olmadığından yalnızca yakalama handler'ına düşer. /api
uçları sadece panel host'unda var olur.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.routing import Host, Mount

from app.config import get_settings
from app.eventbus import EventBus
from app.listeners import http_capture
from app.listeners.dns_server import DNSServer
from app.routers import panel
from app.services.pipeline import Pipeline
from app.storage import Storage

settings = get_settings()

panel_app = FastAPI(title="Kanca Panel")
panel_app.include_router(panel.router)

capture_app = FastAPI(title="Kanca Capture")
capture_app.include_router(http_capture.router)


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage = Storage(settings.db_path)
    await storage.connect()
    bus = EventBus()
    pipeline = Pipeline(storage, bus, settings.group_window_s)

    # Paylaşılan servisleri alt uygulamalara da bağla (mount edilen alt
    # uygulamaların kendi lifespan'i çalışmaz, state'i elle veriyoruz).
    for a in (app, panel_app, capture_app):
        a.state.storage = storage
        a.state.bus = bus
        a.state.pipeline = pipeline

    dns = DNSServer(app.state)
    try:
        await dns.start()
    except OSError as exc:
        # 53 portu doluysa (ör. systemd-resolved) HTTP yakalama yine çalışsın.
        app.state.dns_error = str(exc)
        dns = None

    try:
        yield
    finally:
        if dns is not None:
            await dns.stop()
        await pipeline.shutdown()
        await storage.close()


app = FastAPI(lifespan=lifespan, title="Kanca")
# Host tabanlı yönlendirme: önce panel host'u, sonra her şey yakalamaya düşer.
app.router.routes = [
    Host(settings.panel_domain, app=panel_app, name="panel"),
    Mount("/", app=capture_app, name="capture"),
]
