"""Phase 2 Task 3: suppression API CRUD + RBAC + audit (TestClient, sqlite)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio


def _client_for(role="admin"):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.core.database import Base
    import app.models.entities as E  # noqa: register
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext
    from fastapi.testclient import TestClient

    engine = create_async_engine("sqlite+aiosqlite://")
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as s:
            s.add(E.Organization(id="org-a", name="default"))
            s.add(E.User(id="u1", org_id="org-a", email="admin@x",
                         password_hash="x", role=E.UserRole.ADMIN, is_active=True))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())

    async def _db():
        async with maker() as s:
            yield s

    async def _user():
        return AuthContext(user_id="u1", email="admin@x" if role == "admin" else "a@x",
                           org_id="org-a", role=role, via="jwt")

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    try:
        return TestClient(app, raise_server_exceptions=False), maker
    finally:
        pass


def test_suppression_crud_and_audit():
    client, maker = _client_for("admin")
    try:
        r = client.post("/api/v1/suppressions", json={
            "rule_id": "weak-cipher-suite", "scope": {"cidrs": ["10.0.0.0/8"]},
            "reason": "legacy scanner", "expires_days": 30})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "approved"  # admin auto-approved
        sid = body["id"]
        r = client.get("/api/v1/suppressions")
        assert r.status_code == 200 and len(r.json()) == 1
        r = client.get("/api/v1/suppressions/expiring-soon?days=60")
        assert r.status_code == 200 and len(r.json()) == 1
        r = client.patch(f"/api/v1/suppressions/{sid}", json={"status": "revoked"})
        assert r.status_code == 200 and r.json()["status"] == "revoked"
        # audit trail written
        r = client.get("/api/v1/audit?action=suppression.create")
        assert r.status_code == 200 and len(r.json()) == 1
        r = client.get("/api/v1/audit?action=suppression.update")
        assert r.status_code == 200 and len(r.json()) == 1
    finally:
        from app.api.main import app
        from app.core.database import get_db
        from app.core.auth import get_current_user
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


def test_analyst_request_goes_pending_when_approval_required():
    from app.core import config as cfg
    old = cfg.settings.SUPPRESSION_REQUIRE_APPROVAL
    cfg.settings.SUPPRESSION_REQUIRE_APPROVAL = True
    client, _ = _client_for("analyst")
    try:
        r = client.post("/api/v1/suppressions", json={
            "rule_id": "rc4-cipher", "scope": {}, "reason": "old printer"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "pending"
    finally:
        cfg.settings.SUPPRESSION_REQUIRE_APPROVAL = old
        from app.api.main import app
        from app.core.database import get_db
        from app.core.auth import get_current_user
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)
