"""SQLite (WAL) depolama katmanı.

Tek kullanıcılı dağıtımda Redis'e gerek yoktur; geçmiş kalıcı tutulur ve
içinde arama yapılır. Ham etkileşim base64 ile, parsed/ai_report JSON ile
saklanır.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

import aiosqlite
from nopanic import retry

from app.models import Hook, Interaction, MockConfig, Protocol


# SQLite WAL'de eşzamanlı yazımlar (HTTP + DNS + pipeline) kısa süreli
# "database is locked" verebilir. Yalnızca bu geçici hatada tekrar dene;
# sözdizimi/şema hataları gibi kalıcı OperationalError'larda hemen pes et.
_on_locked = retry(
    attempts=5,
    on=sqlite3.OperationalError,
    backoff=0.05,
    giveup=lambda exc: "locked" not in str(exc).lower(),
    name="db_write",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hooks (
    token       TEXT PRIMARY KEY,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    mock_config TEXT NOT NULL,
    notify      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS interactions (
    id          TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    source_host TEXT,
    raw_b64     TEXT NOT NULL,
    parsed      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    ai_report   TEXT,
    group_id    TEXT
);

CREATE INDEX IF NOT EXISTS idx_inter_token_ts
    ON interactions (token, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_inter_protocol
    ON interactions (protocol);
"""


def _utf8_safe(obj):
    """Yakalanan veride olabilecek lone-surrogate / geçersiz UTF-8'i temizler,
    böylece SQLite TEXT sütununa yazılan değer her zaman geçerli UTF-8 olur."""
    if isinstance(obj, str):
        return obj.encode("utf-8", "replace").decode("utf-8")
    if isinstance(obj, list):
        return [_utf8_safe(x) for x in obj]
    if isinstance(obj, dict):
        return {_utf8_safe(k): _utf8_safe(v) for k, v in obj.items()}
    return obj


def _dumps(obj) -> str:
    return json.dumps(_utf8_safe(obj), ensure_ascii=False)


class Storage:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        # Yakalanan veri ikili/bozuk olabilir; eski kayıtlar geçersiz UTF-8
        # içerse bile okuma çökmesin diye bozuk byte'ları değiştirerek çöz.
        self._db.text_factory = lambda b: b.decode("utf-8", "replace")
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA foreign_keys=ON;")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Storage.connect() çağrılmadı")
        return self._db

    # --- Hooks ---------------------------------------------------------
    @_on_locked
    async def create_hook(self, hook: Hook) -> None:
        await self.db.execute(
            "INSERT INTO hooks (token, label, created_at, mock_config, notify) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                hook.token,
                hook.label,
                hook.created_at.isoformat(),
                hook.mock_config.model_dump_json(),
                int(hook.notify),
            ),
        )
        await self.db.commit()

    async def get_hook(self, token: str) -> Optional[Hook]:
        async with self.db.execute(
            "SELECT token, label, created_at, mock_config, notify "
            "FROM hooks WHERE token = ?",
            (token,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return Hook(
            token=row[0],
            label=row[1],
            created_at=datetime.fromisoformat(row[2]),
            mock_config=MockConfig.model_validate_json(row[3]),
            notify=bool(row[4]),
        )

    async def list_hooks(self) -> list[Hook]:
        async with self.db.execute(
            "SELECT token, label, created_at, mock_config, notify "
            "FROM hooks ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [
            Hook(
                token=r[0],
                label=r[1],
                created_at=datetime.fromisoformat(r[2]),
                mock_config=MockConfig.model_validate_json(r[3]),
                notify=bool(r[4]),
            )
            for r in rows
        ]

    @_on_locked
    async def update_mock(self, token: str, mock: MockConfig) -> bool:
        cur = await self.db.execute(
            "UPDATE hooks SET mock_config = ? WHERE token = ?",
            (mock.model_dump_json(), token),
        )
        await self.db.commit()
        return cur.rowcount > 0

    @_on_locked
    async def delete_hook(self, token: str) -> bool:
        cur = await self.db.execute("DELETE FROM hooks WHERE token = ?", (token,))
        await self.db.execute("DELETE FROM interactions WHERE token = ?", (token,))
        await self.db.commit()
        return cur.rowcount > 0

    # --- Interactions --------------------------------------------------
    @_on_locked
    async def save_interaction(self, it: Interaction) -> None:
        await self.db.execute(
            "INSERT INTO interactions "
            "(id, token, protocol, timestamp, source_ip, source_host, "
            " raw_b64, parsed, size_bytes, ai_report, group_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                it.id,
                it.token,
                it.protocol.value,
                it.timestamp.isoformat(),
                it.source_ip,
                it.source_host,
                base64.b64encode(it.raw).decode("ascii"),
                _dumps(it.parsed),
                it.size_bytes,
                _dumps(it.ai_report) if it.ai_report else None,
                it.group_id,
            ),
        )
        await self.db.commit()

    @_on_locked
    async def set_ai_report(self, interaction_id: str, report: dict) -> None:
        await self.db.execute(
            "UPDATE interactions SET ai_report = ? WHERE id = ?",
            (_dumps(report), interaction_id),
        )
        await self.db.commit()

    async def list_interactions(
        self, token: Optional[str] = None, limit: int = 100
    ) -> list[Interaction]:
        if token:
            query = (
                "SELECT id, token, protocol, timestamp, source_ip, source_host, "
                "raw_b64, parsed, size_bytes, ai_report, group_id "
                "FROM interactions WHERE token = ? ORDER BY timestamp DESC LIMIT ?"
            )
            params: tuple = (token, limit)
        else:
            query = (
                "SELECT id, token, protocol, timestamp, source_ip, source_host, "
                "raw_b64, parsed, size_bytes, ai_report, group_id "
                "FROM interactions ORDER BY timestamp DESC LIMIT ?"
            )
            params = (limit,)
        async with self.db.execute(query, params) as cur:
            rows = await cur.fetchall()
        return [self._row_to_interaction(r) for r in rows]

    @staticmethod
    def _row_to_interaction(r) -> Interaction:
        return Interaction(
            id=r[0],
            token=r[1],
            protocol=Protocol(r[2]),
            timestamp=datetime.fromisoformat(r[3]),
            source_ip=r[4],
            source_host=r[5],
            raw=base64.b64decode(r[6]),
            parsed=json.loads(r[7]),
            size_bytes=r[8],
            ai_report=json.loads(r[9]) if r[9] else None,
            group_id=r[10],
        )
