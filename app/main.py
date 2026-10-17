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

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.routing import Host, Mount

log = logging.getLogger("kanca")

from app.config import get_settings
from app.eventbus import EventBus
from app.listeners import http_capture
from app.listeners.dns_server import DNSServer
from app.listeners.tcp_listeners import LDAPServer, SMTPServer
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
        pipeline = Pipeline(storage, bus, settings.group_window_s,
                            settings.ai_max_per_group)

        # Paylaşılan servisleri (mount edilen) alt uygulamalara da bağla;
        # onların kendi lifespan'i çalışmadığından state'i elle veriyoruz.
        for a in (app, *extra_apps):
            a.state.storage = storage
            a.state.bus = bus
            a.state.pipeline = pipeline

        # PUBLIC_IP geçerli mi? (DNS A yanıtı bunu kullanır; geçersizse DNS
        # sunucusu her yanıtta patlar — sessiz kalmasın diye erken uyar.)
        try:
            ipaddress.ip_address(settings.public_ip)
        except ValueError:
            log.warning(
                "PUBLIC_IP gecersiz: %r — DNS yanitlari calismayacak. "
                ".env'de gercek IP'yi ayarla.",
                settings.public_ip,
            )

        dns = DNSServer(app.state)
        try:
            await dns.start()
            log.info(
                "DNS dinleyici basladi (udp/tcp %s), A yaniti -> %s",
                settings.dns_udp_port,
                settings.public_ip,
            )
        except OSError as exc:
            # 53 portu dolu/yetkisizse HTTP yakalama yine çalışsın.
            app.state.dns_error = str(exc)
            log.warning("DNS dinleyici baslatilamadi (%s): %s", settings.dns_udp_port, exc)
            dns = None

        # SMTP / LDAP dinleyiciler (her biri bağımsız; biri açılmazsa diğerleri
        # çalışmaya devam eder). Port 25 çoğu sağlayıcıda kapalı olabilir.
        tcp_servers = []
        for name, port, cls in (
            ("SMTP", settings.smtp_port, SMTPServer),
            ("LDAP", settings.ldap_port, LDAPServer),
        ):
            if port <= 0:
                continue
            srv = cls(app.state)
            try:
                await srv.start()
                log.info("%s dinleyici basladi (port %s)", name, port)
                tcp_servers.append(srv)
            except OSError as exc:
                log.warning("%s dinleyici baslatilamadi (%s): %s", name, port, exc)

        # Periyodik DB temizliği (retention): DB sınırsız büyümesin.
        async def _cleanup_loop():
            while True:
                try:
                    await asyncio.sleep(settings.cleanup_interval_s)
                    n = await storage.cleanup(
                        settings.max_interactions_per_token,
                        settings.interaction_ttl_days,
                    )
                    if n:
                        log.info("Temizlik: %d eski kayit silindi", n)
                except asyncio.CancelledError:
                    break
                except Exception as exc:  # temizlik hatası servisi düşürmesin
                    log.warning("Temizlik hatasi: %s", exc)

        cleanup_task = asyncio.create_task(_cleanup_loop())

        try:
            yield
        finally:
            cleanup_task.cancel()
            if dns is not None:
                await dns.stop()
            for srv in tcp_servers:
                await srv.stop()
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
