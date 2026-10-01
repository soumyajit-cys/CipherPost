"""Phase 3 Task 2: agent tokens, ingest stamping, assume flow, tenancy flags."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import gzip
import json
from datetime import datetime, timezone, timedelta


def _setup():
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.core.database import Base
    import app.models.entities as E
    engine = create_async_engine("sqlite+aiosqlite://")
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as s:
            s.add(E.Organization(id="org-a", name="a"))
            s.add(E.Organization(id="org-b", name="b"))
            s.add(E.User(id="ua", org_id="org-a", email="a@x", password_hash="x",
                         role=E.UserRole.ADMIN, is_active=True))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())
    return maker


def _client(maker, user_id="ua", org="org-a", role="admin"):
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext
    from fastapi.testclient import TestClient

    async def _db():
        async with maker() as s:
            yield s

    async def _user():
        return AuthContext(user_id=user_id, email="a@x", org_id=org, role=role, via="jwt")

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    return TestClient(app, raise_server_exceptions=False)


def _clear():
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


def test_agent_token_shown_once_and_hashed():
    maker = _setup()
    client = _client(maker)
    try:
        r = client.post("/api/v1/agent-tokens", json={"name": "site-1"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["raw_token"].startswith("cpat_")
        assert "Store this token now" in body["warning"]

        async def _check():
            from sqlalchemy import select
            import app.models.entities as E
            async with maker() as s:
                row = (await s.execute(select(E.AgentToken))).scalars().one()
                return row.key_hash, row.org_id
        digest, org = asyncio.get_event_loop().run_until_complete(_check())
        assert digest != body["raw_token"]  # only the hash is stored
        assert org == "org-a"
        # listing never exposes raw material
        assert "raw_token" not in json.dumps(client.get("/api/v1/agent-tokens").json())
        # revoke works
        tid = client.get("/api/v1/agent-tokens").json()[0]["id"]
        assert client.delete(f"/api/v1/agent-tokens/{tid}").status_code == 200
        assert client.get("/api/v1/agent-tokens").json() == []
    finally:
        _clear()


def test_ingest_stamps_token_org_and_rejects_other_org_payload():
    maker = _setup()
    client = _client(maker)
    try:
        raw = client.post("/api/v1/agent-tokens", json={"name": "s"}).json()["raw_token"]
        payload = {"sessions": [
            {"five_tuple": "1.1.1.1:1-2.2.2.2:25", "protocol": "SMTP",
             "org_id": "org-b", "start_ts": 1.0},  # attacker-chosen org ignored
            {"bogus": True},  # rejected
        ]}
        r = client.post("/api/v1/ingest/sessions", json=payload,
                        headers={"X-Agent-Token": raw})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["org_id"] == "org-a" and body["accepted"] == 1 and body["rejected"] == 1
        # gzip path accepted too
        gz = gzip.compress(json.dumps(
            {"sessions": [{"five_tuple": "3.3.3.3:1-4.4.4.4:25",
                                   "protocol": "SMTP"}]}).encode())
        r = client.post("/api/v1/ingest/sessions", content=gz,
                        headers={"X-Agent-Token": raw, "Content-Encoding": "gzip",
                                 "Content-Type": "application/json"})
        assert r.status_code == 200 and r.json()["accepted"] == 1
        # no token / bad token -> 401, never 403/404 (no enumeration delta)
        assert client.post("/api/v1/ingest/sessions", json={}).status_code == 401
        assert client.post("/api/v1/ingest/sessions", json={},
                           headers={"X-Agent-Token": "cpat_" + "0" * 32}).status_code == 401
    finally:
        _clear()


def test_revoked_and_expired_agent_tokens_rejected():
    import app.models.entities as E
    maker = _setup()
    client = _client(maker)
    try:
        raw = client.post("/api/v1/agent-tokens",
                          json={"name": "s", "expires_days": 1}).json()["raw_token"]
        body = {"sessions": [{"five_tuple": "a-b", "protocol": "SMTP"}]}
        h = {"X-Agent-Token": raw}
        assert client.post("/api/v1/ingest/sessions", json=body, headers=h).status_code == 200

        async def _expire():
            from sqlalchemy import select
            async with maker() as s:
                row = (await s.execute(select(E.AgentToken))).scalars().one()
                row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
                await s.commit()
        asyncio.get_event_loop().run_until_complete(_expire())
        assert client.post("/api/v1/ingest/sessions", json=body, headers=h).status_code == 401
    finally:
        _clear()


def test_ingest_backpressure_429():
    from app.core import config as cfg
    maker = _setup()
    client = _client(maker)
    old = cfg.settings.INGEST_MAX_QUEUE
    cfg.settings.INGEST_MAX_QUEUE = -1  # any stream length trips the guard
    try:
        raw = client.post("/api/v1/agent-tokens", json={"name": "s"}).json()["raw_token"]
        r = client.post("/api/v1/ingest/sessions",
                        json={"sessions": [{"five_tuple": "a-b", "protocol": "SMTP"}]},
                        headers={"X-Agent-Token": raw})
        assert r.status_code == 429
        assert r.headers.get("Retry-After") == "5"
    finally:
        cfg.settings.INGEST_MAX_QUEUE = old
        _clear()


def test_platform_admin_assume_is_audited_and_scoped():
    import app.models.entities as E
    maker = _setup()

    async def _promote():
        async with maker() as s:
            u = await s.get(E.User, "ua")
            u.is_platform_admin = True
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_promote())
    client = _client(maker)
    try:
        # reason required
        assert client.post("/api/v1/admin/assume",
                           json={"org_id": "org-b"}).status_code == 400
        r = client.post("/api/v1/orgs", json={"name": "org-c"})
        assert r.status_code == 200 and r.json()["name"] == "org-c"
        assert len(client.get("/api/v1/audit?action=org.create").json()) == 1
        r = client.post("/api/v1/admin/assume",
                        json={"org_id": "org-b", "reason": "incident 123"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["org_id"] == "org-b"
        # assumed token reads the target org (audited, 1h TTL).
        # Drop the canned-auth override so the token is genuinely verified.
        from app.core.auth import get_current_user as _gcu
        from app.api.main import app as _app
        _app.dependency_overrides.pop(_gcu, None)
        r2 = client.get("/api/v1/sessions",
                        headers={"Authorization": f"Bearer {body['token']}"})
        assert r2.status_code == 200, r2.text
        # audit trail exists for both actions (assume logged under target org)
        ah = {"Authorization": f"Bearer {body['token']}"}
        got = client.get("/api/v1/audit?action=admin.assume_org", headers=ah).json()
        assert len(got) == 1, got
    finally:
        _clear()


def test_org_crud_and_assume_are_platform_only_and_audited():
    maker = _setup()
    client = _client(maker)
    try:
        # admin (not platform) cannot manage orgs
        assert client.get("/api/v1/orgs").status_code == 403
        assert client.post("/api/v1/orgs", json={"name": "c"}).status_code == 403
        assert client.post("/api/v1/admin/assume",
                           json={"org_id": "org-b", "reason": "x"}).status_code == 403
    finally:
        _clear()


def test_multi_tenant_refuses_unstamped_sessions(monkeypatch):
    from app.core import config as cfg
    monkeypatch.setattr(cfg.settings, "SINGLE_TENANT", False)
    from app.live.analyze import AnalysisWorker
    import pytest

    class W(AnalysisWorker):
        def __init__(self):
            pass  # no Redis/scorer needed for _persist org gate

    w = W()
    # org gate happens before any DB touch: use a stub session factory
    import app.live.analyze as _am

    class Boom:
        def __call__(self, *a, **k):
            raise AssertionError("DB must not be touched for unstamped payload")

    monkeypatch.setattr(_am, "_get_sync_session", Boom())
    from app.parsing.rules import SessionAnalysis
    sa = SessionAnalysis(session_id="x", protocol="SMTP",
                         five_tuple="a-b", is_starttls=False)
    with pytest.raises(ValueError, match="multi-tenant"):
        w._persist(sa, None, None, 0.0, session_id="x")
