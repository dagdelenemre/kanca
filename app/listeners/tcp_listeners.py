"""SMTP ve LDAP OOB dinleyicileri (ham TCP, asyncio).

Her ikisi de aynı Interaction modeline düşer ve pipeline'ı (AI + Telegram)
tetikler. Token yakalanan veriden çıkarılır:
  * SMTP: RCPT TO alanındaki {token}.{base_domain} alanından
  * LDAP: JNDI yolundaki / searchRequest içindeki token'dan

Token çıkarımı için ham baytlarda hem `{token}.{base_domain}` hem de çıplak
32-hex token aranır (ikincisi yalnızca var olan bir kancayla eşleşirse kaydedilir).
"""
from __future__ import annotations

import asyncio
import logging
import re

from app.config import get_settings
from app.models import Interaction, Protocol

log = logging.getLogger("kanca")

_HEX32 = re.compile(rb"\b([0-9a-fA-F]{32})\b")


def _find_token(raw: bytes, base_domain: str) -> str | None:
    """Ham baytlarda token arar: önce {token}.{base_domain}, sonra çıplak 32-hex."""
    base = re.escape(base_domain.encode())
    m = re.search(rb"([0-9a-zA-Z_-]{6,64})\." + base, raw, re.IGNORECASE)
    if m:
        return m.group(1).decode("ascii", "ignore").lower()
    m = _HEX32.search(raw)
    if m:
        return m.group(1).decode("ascii", "ignore").lower()
    return None


async def _record(state, token: str, protocol: Protocol, src: str,
                  raw: bytes, parsed: dict) -> None:
    hook = await state.storage.get_hook(token)
    if hook is None:
        return
    interaction = Interaction(
        token=token, protocol=protocol, source_ip=src,
        raw=raw, size_bytes=len(raw), parsed=parsed,
    )
    await state.storage.save_interaction(interaction)
    await state.bus.publish({
        "id": interaction.id,
        "token": token,
        "protocol": protocol.value,
        "timestamp": interaction.timestamp.isoformat(),
        "source_ip": src,
        "path": parsed.get("summary", protocol.value),
        "method": protocol.value.upper(),
        "size_bytes": interaction.size_bytes,
    })
    if hook.notify:
        asyncio.create_task(state.pipeline.handle(interaction))


# --- SMTP ------------------------------------------------------------
class SMTPServer:
    """Minimal SMTP yanıtlayıcı: diyaloğu yürütür, mesajı yakalar."""

    def __init__(self, app_state) -> None:
        self.state = app_state
        self.settings = get_settings()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", self.settings.smtp_port
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        src = peer[0] if peer else "unknown"
        buf = bytearray()
        rcpt = None
        try:
            writer.write(b"220 kanca ESMTP ready\r\n")
            await writer.drain()
            in_data = False
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=15.0)
                if not line:
                    break
                buf += line
                if len(buf) > 256 * 1024:      # aşırı büyük mesajı sınırla
                    break
                if in_data:
                    if line.rstrip(b"\r\n") == b".":
                        writer.write(b"250 OK queued\r\n")
                        await writer.drain()
                        in_data = False
                    continue
                up = line.strip().upper()
                if up.startswith((b"EHLO", b"HELO")):
                    writer.write(b"250 kanca\r\n")
                elif up.startswith(b"RCPT"):
                    rcpt = line.strip().decode("latin-1", "replace")
                    writer.write(b"250 OK\r\n")
                elif up.startswith(b"DATA"):
                    writer.write(b"354 End with <CR><LF>.<CR><LF>\r\n")
                    in_data = True
                elif up.startswith(b"QUIT"):
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

        raw = bytes(buf)
        token = _find_token(raw, self.settings.base_domain)
        if token:
            await _record(
                self.state, token, Protocol.SMTP, src, raw,
                {"rcpt": rcpt, "summary": rcpt or "SMTP",
                 "preview": raw.decode("latin-1", "replace")[:2000]},
            )


# --- LDAP ------------------------------------------------------------
def _ldap_msgid(data: bytes) -> int:
    # LDAPMessage: 30 len 02 01 <msgid> ...
    if len(data) >= 5 and data[0] == 0x30 and data[2] == 0x02 and data[3] == 0x01:
        return data[4]
    return 1


def _ldap_bind_success(msgid: int) -> bytes:
    # LDAPMessage { messageID, bindResponse { success, "", "" } }
    body = bytes([0x02, 0x01, msgid, 0x61, 0x07,
                  0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])
    return bytes([0x30, len(body)]) + body


class LDAPServer:
    """Minimal LDAP yanıtlayıcı: bind'e başarı döner, searchRequest'i yakalar
    (Log4Shell/JNDI OOB geri aramalarını görmek için)."""

    def __init__(self, app_state) -> None:
        self.state = app_state
        self.settings = get_settings()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", self.settings.ldap_port
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        src = peer[0] if peer else "unknown"
        buf = bytearray()
        try:
            first = await asyncio.wait_for(reader.read(8192), timeout=10.0)
            if first:
                buf += first
                # bind'e başarı dön ki istemci searchRequest göndersin
                try:
                    writer.write(_ldap_bind_success(_ldap_msgid(first)))
                    await writer.drain()
                    second = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                    if second:
                        buf += second
                except (asyncio.TimeoutError, ConnectionError, OSError):
                    pass
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

        raw = bytes(buf)
        if not raw:
            return
        token = _find_token(raw, self.settings.base_domain)
        if token:
            # BER içindeki okunabilir dizgeleri özet olarak çıkar.
            printable = re.sub(rb"[^\x20-\x7e]+", b" ", raw).decode("ascii").strip()
            await _record(
                self.state, token, Protocol.LDAP, src, raw,
                {"summary": "LDAP", "preview": printable[:2000]},
            )
