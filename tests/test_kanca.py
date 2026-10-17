"""Kanca çekirdek testleri.

Çalıştırma: pytest -q  (proje kökünden)

Ortam değişkenleri app import edilmeden ÖNCE ayarlanır (get_settings lru_cache'li).
SMTP/LDAP/DNS dinleyiciler CI'da port bağlamasın diye kapatılır (port 0).
"""
import asyncio
import os
import tempfile

os.environ.setdefault("CAPTURE_MODE", "path")
os.environ.setdefault("ADMIN_TOKEN", "testtoken")
os.environ.setdefault("BASE_DOMAIN", "oob.test")
os.environ.setdefault("PANEL_BASE_URL", "http://localhost:8000")
os.environ.setdefault("DNS_UDP_PORT", "0")
os.environ.setdefault("DNS_TCP_PORT", "0")
os.environ.setdefault("SMTP_PORT", "0")
os.environ.setdefault("LDAP_PORT", "0")
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "kanca_test.db"))

from starlette.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.listeners.http_capture import resolve_token  # noqa: E402
from app.listeners.tcp_listeners import _find_token  # noqa: E402
from app.models import Interaction, Protocol  # noqa: E402
from app.parsing import parse_http_body  # noqa: E402
from app.services.ai import _redact  # noqa: E402
from app.services.pipeline import _max_risk  # noqa: E402
from app.storage import Storage, _utf8_safe  # noqa: E402


# --- saf birim testleri ---------------------------------------------
def test_resolve_token():
    assert resolve_token("abc.oob.test", "oob.test") == "abc"
    assert resolve_token("x.abc.oob.test", "oob.test") == "abc"
    assert resolve_token("oob.test", "oob.test") is None
    assert resolve_token("panel.other.test", "oob.test") is None


def test_find_token():
    base = "oob.test"
    assert _find_token(b"RCPT TO:<v@deadbeef.oob.test>", base) == "deadbeef"
    tok = "a" * 32
    assert _find_token(b"cn=" + tok.encode() + b",dc=x", base) == tok
    assert _find_token(b"hicbir sey yok", base) is None


def test_parse_http_body():
    assert parse_http_body(b'{"a":1}', "application/json") == {"a": 1}
    pairs = parse_http_body(b"a=1&b=2", "application/x-www-form-urlencoded")
    assert ["a", "1"] in pairs
    # bozuk JSON -> fallback (çökmez)
    out = parse_http_body(b"{bozuk", "application/json")
    assert isinstance(out, dict) and "_parse_error" in out


def test_utf8_safe():
    assert _utf8_safe("ab\udcacc") == "ab?c"  # lone surrogate temizlenir
    assert _utf8_safe({"k": "x\udc90"})["k"] == "x?"


def test_raw_serializes_to_base64():
    it = Interaction(token="t", protocol=Protocol.DNS, raw=b"\x00\x90\xac\xff")
    d = it.model_dump(mode="json")
    import base64
    assert base64.b64decode(d["raw"]) == b"\x00\x90\xac\xff"


def test_capture_url_modes():
    s = get_settings()
    assert s.capture_url("tok").endswith("/c/tok/")  # path modu
    assert s.dns_host("tok") == "tok.oob.test"


def test_redact():
    blob = '{"headers":[["cookie","session=secret123"]]}'
    out = _redact(blob)
    assert "secret123" not in out and "[REDACTED]" in out


def test_max_risk():
    reports = [
        {"risk_level": "INFO"}, {"risk_level": "CRITICAL"}, {"risk_level": "LOW"},
    ]
    assert _max_risk(reports)["risk_level"] == "CRITICAL"
    assert _max_risk([])["risk_level"] == "UNKNOWN"


def test_storage_roundtrip_bad_bytes():
    async def run():
        db = os.path.join(tempfile.gettempdir(), "kanca_rt.db")
        if os.path.exists(db):
            os.remove(db)
        st = Storage(db)
        await st.connect()
        it = Interaction(token="z", protocol=Protocol.DNS,
                         raw=b"\xac\xff", parsed={"qname": "bad\udcacname"})
        await st.save_interaction(it)
        items = await st.list_interactions(token="z")  # çökmemeli
        await st.close()
        return items
    items = asyncio.run(run())
    assert len(items) == 1 and items[0].raw == b"\xac\xff"


def test_cleanup_trims_per_token():
    async def run():
        db = os.path.join(tempfile.gettempdir(), "kanca_cl.db")
        if os.path.exists(db):
            os.remove(db)
        st = Storage(db)
        await st.connect()
        for i in range(10):
            await st.save_interaction(Interaction(token="k", protocol=Protocol.HTTP,
                                                   parsed={"path": f"/{i}"}))
        deleted = await st.cleanup(max_per_token=3, ttl_days=0)
        items = await st.list_interactions(token="k", limit=100)
        await st.close()
        return deleted, items
    deleted, items = asyncio.run(run())
    assert deleted == 7 and len(items) == 3


# --- uçtan uca (TestClient, path modu) ------------------------------
def test_e2e_auth_capture_and_cookie():
    import app.main as m
    with TestClient(m.app) as c:
        # auth yok -> 401
        assert c.get("http://t/api/hooks").status_code == 401
        # yanlış token ile login -> 401
        assert c.post("http://t/api/login", json={"token": "yanlis"}).status_code == 401
        # header ile kanca oluştur
        r = c.post("http://t/api/hooks", headers={"X-Admin-Token": "testtoken"},
                   json={"label": "e2e"})
        assert r.status_code == 200
        token = r.json()["token"]
        # yakalama (path modu)
        cap = c.post(f"http://t/c/{token}/login", json={"u": "admin"})
        assert cap.status_code == 200
        # cookie auth: login sonrası header olmadan erişim
        assert c.post("http://t/api/login", json={"token": "testtoken"}).status_code == 200
        lst = c.get(f"http://t/api/hooks/{token}/interactions")  # cookie ile
        assert lst.status_code == 200 and len(lst.json()) == 1
        assert lst.json()[0]["parsed"]["path"] == "/login"


def test_e2e_probe_js():
    import app.main as m
    with TestClient(m.app) as c:
        token = c.post("http://t/api/hooks", headers={"X-Admin-Token": "testtoken"},
                       json={}).json()["token"]
        r = c.get(f"http://t/c/{token}/p.js")
        assert r.status_code == 200
        assert "sendBeacon" in r.text and f"/c/{token}/xss" in r.text
        assert r.headers.get("access-control-allow-origin") == "*"
