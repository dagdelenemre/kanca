"""HTTP(S) yakalama uçları + mock motoru.

Yakalama vhost'u (base_domain altındaki herhangi bir alt alan) üzerindeki tüm
istekleri yakalar. Host header'ından token çözülür, istek kaydedilir, arka plan
AI/bildirim hattı tetiklenir ve kancanın mock kuralına göre yanıt döner.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Request, Response

from app.config import get_settings
from app.models import Interaction, MockConfig, Protocol
from app.parsing import multi_items, parse_http_body

router = APIRouter()


def resolve_token(host: str, base_domain: str) -> str | None:
    """`{token}.oob...` veya `x.{token}.oob...` host'undan token çıkarır."""
    host = (host or "").split(":")[0].rstrip(".").lower()
    base = base_domain.rstrip(".").lower()
    if host == base or not host.endswith("." + base):
        return None
    prefix = host[: -(len(base) + 1)]           # base_domain kısmını at
    labels = prefix.split(".")
    return labels[-1] if labels and labels[-1] else None


async def _read_limited(request: Request, limit: int) -> tuple[bytes, bool]:
    """Gövdeyi akarak okur; limit aşılırsa keser. (veri, kesildi_mi)."""
    # Content-Length erken ret için kontrol edilir.
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        return b"", True
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return b"".join(chunks), True
        chunks.append(chunk)
    return b"".join(chunks), False


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def capture(path: str, request: Request, background_tasks: BackgroundTasks):
    settings = get_settings()
    storage = request.app.state.storage
    bus = request.app.state.bus
    pipeline = request.app.state.pipeline

    token = resolve_token(request.headers.get("host", ""), settings.base_domain)
    if token is None:
        return Response(content="Kanca bulunamadı", status_code=404)

    hook = await storage.get_hook(token)
    if hook is None:
        return Response(content="Kanca bulunamadı", status_code=404)

    raw, truncated = await _read_limited(request, settings.max_body_bytes)
    content_type = request.headers.get("content-type", "")

    interaction = Interaction(
        token=token,
        protocol=Protocol.HTTP,
        source_ip=request.client.host if request.client else "unknown",
        raw=raw,
        size_bytes=len(raw),
        parsed={
            "method": request.method,
            "path": "/" + path,
            "query": multi_items(request.query_params.multi_items()),
            "headers": multi_items(request.headers.items()),
            "body": parse_http_body(raw, content_type),
            "truncated": truncated,
        },
    )

    await storage.save_interaction(interaction)
    await bus.publish(_summary(interaction))
    if hook.notify:
        background_tasks.add_task(pipeline.handle, interaction)

    return _mock_response(hook.mock_config)


def _mock_response(cfg: MockConfig) -> Response:
    # delay not: yanıt öncesi gecikme. (BackgroundTasks yanıttan sonra çalışır.)
    headers = dict(cfg.headers)
    return _DelayedResponse(
        content=cfg.body,
        status_code=cfg.status_code,
        headers=headers,
        delay_ms=cfg.delay_ms,
    )


class _DelayedResponse(Response):
    def __init__(self, *args, delay_ms: int = 0, **kwargs):
        self._delay_ms = delay_ms
        super().__init__(*args, **kwargs)

    async def __call__(self, scope, receive, send):
        if self._delay_ms > 0:
            await asyncio.sleep(self._delay_ms / 1000.0)
        await super().__call__(scope, receive, send)


def _summary(it: Interaction) -> dict:
    """SSE için hafif özet (tam ham gövde değil)."""
    return {
        "id": it.id,
        "token": it.token,
        "protocol": it.protocol.value,
        "timestamp": it.timestamp.isoformat(),
        "source_ip": it.source_ip,
        "method": it.parsed.get("method"),
        "path": it.parsed.get("path") or it.parsed.get("qname"),
        "size_bytes": it.size_bytes,
    }
