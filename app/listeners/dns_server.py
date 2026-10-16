"""Asenkron DNS dinleyici (UDP + TCP).

base_domain altına gelen sorguları yakalar, en sağdaki etiketten token çözer ve
A/AAAA sorgularına VPS'in public IP'sini yanıtlar (hedefin HTTP için geri
bağlanabilmesi için). Her sorgu bir Interaction olarak kaydedilir.

Not: 53 portunu dinlemek genelde root/yetki ister; VPS'te systemd-resolved vb.
53'ü kullanıyorsa devre dışı bırakılmalıdır.
"""
from __future__ import annotations

import asyncio
import struct

from dnslib import QTYPE, RR, TXT, A, DNSRecord

from app.config import get_settings
from app.models import Interaction, Protocol


def _resolve_token(qname: str, base_domain: str) -> str | None:
    name = qname.rstrip(".").lower()
    base = base_domain.rstrip(".").lower()
    if name == base or not name.endswith("." + base):
        return None
    prefix = name[: -(len(base) + 1)]
    labels = prefix.split(".")
    return labels[-1] if labels and labels[-1] else None


class _Handler:
    """Ortak işleme mantığı (UDP ve TCP paylaşır)."""

    def __init__(self, app_state) -> None:
        self.state = app_state
        self.settings = get_settings()

    def build_reply(self, data: bytes, source_ip: str) -> bytes | None:
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return None

        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        # ACME DNS-01: _acme-challenge.{base_domain} TXT sorgusunu, certbot'un
        # paylaşımlı dosyaya yazdığı değer(ler)le yanıtla (*.oob wildcard TLS).
        acme_name = f"_acme-challenge.{self.settings.base_domain}".rstrip(".").lower()
        if qtype in ("TXT", "ANY") and qname.rstrip(".").lower() == acme_name:
            for val in self._acme_values():
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(val), ttl=1))
            return reply.pack()

        token = _resolve_token(qname, self.settings.base_domain)
        if token is not None:
            asyncio.create_task(self._record(token, qname, qtype, source_ip, data))

        if qtype in ("A", "ANY"):
            reply.add_answer(
                RR(qname, QTYPE.A, rdata=A(self.settings.public_ip), ttl=60)
            )
        return reply.pack()

    def _acme_values(self) -> list[str]:
        try:
            with open(self.settings.acme_challenge_path, encoding="utf-8") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    async def _record(
        self, token: str, qname: str, qtype: str, source_ip: str, raw: bytes
    ) -> None:
        storage = self.state.storage
        hook = await storage.get_hook(token)
        if hook is None:
            return
        interaction = Interaction(
            token=token,
            protocol=Protocol.DNS,
            source_ip=source_ip,
            raw=raw,
            size_bytes=len(raw),
            parsed={"qname": qname, "qtype": qtype},
        )
        await storage.save_interaction(interaction)
        await self.state.bus.publish(
            {
                "id": interaction.id,
                "token": token,
                "protocol": "dns",
                "timestamp": interaction.timestamp.isoformat(),
                "source_ip": source_ip,
                "path": qname,
                "method": qtype,
                "size_bytes": interaction.size_bytes,
            }
        )
        if hook.notify:
            asyncio.create_task(self.state.pipeline.handle(interaction))


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: _Handler) -> None:
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        reply = self.handler.build_reply(data, addr[0])
        if reply and self.transport:
            self.transport.sendto(reply, addr)


async def _handle_tcp(handler: _Handler, reader, writer) -> None:
    try:
        length_bytes = await reader.readexactly(2)
        (length,) = struct.unpack("!H", length_bytes)
        data = await reader.readexactly(length)
        peer = writer.get_extra_info("peername")
        reply = handler.build_reply(data, peer[0] if peer else "unknown")
        if reply:
            writer.write(struct.pack("!H", len(reply)) + reply)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


class DNSServer:
    def __init__(self, app_state) -> None:
        self._handler = _Handler(app_state)
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        s = self._handler.settings
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._handler),
            local_addr=("0.0.0.0", s.dns_udp_port),
        )
        self._tcp_server = await asyncio.start_server(
            lambda r, w: _handle_tcp(self._handler, r, w),
            "0.0.0.0",
            s.dns_tcp_port,
        )

    async def stop(self) -> None:
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
