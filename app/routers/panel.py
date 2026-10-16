"""Yönetim arayüzü API'si (panel_domain üzerinde, auth'lu).

Kanca oluşturma/listeleme/silme, mock güncelleme, etkileşim geçmişi ve canlı
yayın (SSE). Tüm uçlar require_admin ile korunur; SSE token'ı query ile de
kabul eder (EventSource header gönderemez).
"""
from __future__ import annotations

import asyncio
import json
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from app.config import get_settings
from app.models import Hook, MockConfig
from app.routers.auth import require_admin

router = APIRouter()


class CreateHookIn(BaseModel):
    label: str = ""
    notify: bool = True


@router.post("/api/hooks", dependencies=[Depends(require_admin)])
async def create_hook(body: CreateHookIn, request: Request):
    settings = get_settings()
    hook = Hook(label=body.label, notify=body.notify)
    await request.app.state.storage.create_hook(hook)
    return {
        "token": hook.token,
        "http_url": f"https://{hook.token}.{settings.base_domain}/",
        "dns_host": f"{hook.token}.{settings.base_domain}",
    }


@router.get("/api/hooks", dependencies=[Depends(require_admin)])
async def list_hooks(request: Request):
    hooks = await request.app.state.storage.list_hooks()
    return [h.model_dump(mode="json") for h in hooks]


@router.put("/api/hooks/{token}/mock", dependencies=[Depends(require_admin)])
async def update_mock(token: str, mock: MockConfig, request: Request):
    ok = await request.app.state.storage.update_mock(token, mock)
    if not ok:
        raise HTTPException(status_code=404, detail="Kanca bulunamadı")
    return {"ok": True}


@router.delete("/api/hooks/{token}", dependencies=[Depends(require_admin)])
async def delete_hook(token: str, request: Request):
    ok = await request.app.state.storage.delete_hook(token)
    if not ok:
        raise HTTPException(status_code=404, detail="Kanca bulunamadı")
    return {"ok": True}


@router.get("/api/hooks/{token}/interactions", dependencies=[Depends(require_admin)])
async def hook_interactions(token: str, request: Request, limit: int = 100):
    items = await request.app.state.storage.list_interactions(token=token, limit=limit)
    return [i.model_dump(mode="json") for i in items]


@router.get("/api/interactions", dependencies=[Depends(require_admin)])
async def all_interactions(request: Request, limit: int = 100):
    items = await request.app.state.storage.list_interactions(limit=limit)
    return [i.model_dump(mode="json") for i in items]


@router.get("/api/stream")
async def stream(request: Request, token: str = Query(default="")):
    # EventSource header gönderemediği için SSE auth'u query ile kabul edilir.
    settings = get_settings()
    if not token or not secrets.compare_digest(token, settings.admin_token):
        raise HTTPException(status_code=401, detail="Yetkisiz")

    bus = request.app.state.bus
    queue = await bus.subscribe()

    async def gen():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"   # proxy'lerin bağlantıyı kesmesini önler
        finally:
            await bus.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/", response_class=HTMLResponse)
async def index():
    # v1: panel UI için yer tutucu. Gerçek arayüz ayrı aşamada eklenecek.
    return HTMLResponse(
        "<!doctype html><meta charset='utf-8'>"
        "<title>Kanca</title>"
        "<h1>Kanca paneli</h1>"
        "<p>API hazır. Arayüz sonraki aşamada eklenecek.</p>"
    )
