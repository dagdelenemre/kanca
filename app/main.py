"""Uygulama girişi: yakalama moduna göre yönlendirme + DNS dinleyici.

CAPTURE_MODE=path (yerel/geliştirme, varsayılan):
  Tek uygulama. Panel ve /api aynı origin'de; yakalama /c/{token}/... altında.
  localhost'ta alt alan ayarlanamadığı için pratik olan budur.

CAPTURE_MODE=host (üretim/VPS):
  Host tabanlı ayrım (güvenlik açısından kritik):
    * panel_domain → panel_app (auth'lu /api ve arayüz)
    * diğer host'lar (base_domain alt alanları) → capture_app (yakalama)
  Böylece {token}.oob.../api/hooks adresinde /api HİÇ var olmaz; yalnızca
  yakalama handler'ına düşer.
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


def _make_lifespan(*extra_apps: FastAPI):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        storage = Storage(settings.db_path)
        await storage.connect()
        bus = EventBus()
        pipeline = Pipeline(storage, bus, settings.group_window_s)

        # Paylaşılan servisleri (mount edilen) alt uygulamalara da bağla;
        # onların kendi lifespan'i çalışmadığından state'i elle veriyoruz.
        for a in (app, *extra_apps):
            a.state.storage = storage
            a.state.bus = bus
            a.state.pipeline = pipeline

        dns = DNSServer(app.state)
        try:
            await dns.start()
        except OSError as exc:
            # 53 portu dolu/yetkisizse HTTP yakalama yine çalışsın.
            app.state.dns_error = str(exc)
            dns = None

        try:
            yield
        finally:
            if dns is not None:
                await dns.stop()
            await pipeline.shutdown()
            await storage.close()

    return lifespan


if settings.capture_mode == "host":
    panel_app = FastAPI(title="Kanca Panel")
    panel_app.include_router(panel.router)
    capture_app = FastAPI(title="Kanca Capture")
    capture_app.include_router(http_capture.host_router)

    app = FastAPI(lifespan=_make_lifespan(panel_app, capture_app), title="Kanca")
    app.router.routes = [
        Host(settings.panel_domain, app=panel_app, name="panel"),
        Mount("/", app=capture_app, name="capture"),
    ]
else:
    # path modu: tek uygulama, panel + /c/{token}/...
    app = FastAPI(lifespan=_make_lifespan(), title="Kanca")
    app.include_router(panel.router)
    app.include_router(http_capture.path_router)
