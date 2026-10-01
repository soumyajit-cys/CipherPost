"""Phase 3 Task 8: feedback labels (org isolation, precision, export)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
from datetime import datetime, timezone


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
            now = datetime.now(timezone.utc)
            for org in ("org-a", "org-b"):
                s.add(E.Organization(id=org, name=org))
                s.add(E.User(id="u-" + org, org_id=org, email=f"{org}@x",
                             password_hash="x", role=E.UserRole.ANALYST, is_active=True))
                s.add(E.AnalysisJob(id="j-" + org, filename="x", pcap_path="x",
                                     status=E.JobStatus.COMPLETED, org_id=org, created_at=now))
                s.add(E.Session(id="s-" + org, job_id="j-" + org, protocol="SMTP",
                                five_tuple="a-b", src_ip="a", dst_ip="b",
                                src_port=1, dst_port=2, org_id=org, created_at=now))
                s.add(E.Finding(session_id="s-" + org, rule_id="weak-cipher-suite",
                                rule_name="w", severity=E.Severity.HIGH, title="t",
                                description="d", reference="", created_at=now))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())
    return maker


def _client(maker, org="org-a"):
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext
    from fastapi.testclient import TestClient

    async def _db():
        async with maker() as s:
            yield s

    holder = {"org": org}

    async def _user():
        o = holder["org"]
        return AuthContext(user_id="u-" + o, email=f"{o}@x",
                           org_id=o, role="analyst", via="jwt")

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    client = TestClient(app, raise_server_exceptions=False)
    client.holder = holder  # type: ignore[attr-defined]
    return client


def _as(client, org):
    client.holder["org"] = org  # type: ignore[attr-defined]
    return client


def _clear():
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


def _finding_id(client):
    return client.get("/api/v1/findings").json()[0]["id"]


def test_feedback_submit_isolated_and_audited():
    maker = _setup()
    client = _client(maker, "org-a")  # single client; identity via _as()
    try:
        fa = _finding_id(client)
        # bad verdict rejected
        assert client.post(f"/api/v1/findings/{fa}/feedback",
                           json={"verdict": "maybe"}).status_code == 400
        r = client.post(f"/api/v1/findings/{fa}/feedback",
                        json={"verdict": "false_positive", "comment": "lab scanner"})
        assert r.status_code == 200
        # other org's finding id is not found (no cross-org write)
        fb = _finding_id(_as(client, "org-b"))
        assert _as(client, "org-a").post(
            f"/api/v1/findings/{fb}/feedback",
            json={"verdict": "confirmed"}).status_code == 404
        # lists are org-scoped; audit written
        assert len(client.get("/api/v1/feedback").json()) == 1
        assert _as(client, "org-b").get("/api/v1/feedback").json() == []
        _as(client, "org-a")
        assert len(client.get("/api/v1/audit?action=finding.feedback").json()) == 1
    finally:
        _clear()


def test_precision_math_and_export():
    maker = _setup()
    client = _client(maker, "org-a")
    try:
        fa = _finding_id(client)
        client.post(f"/api/v1/findings/{fa}/feedback", json={"verdict": "confirmed"})
        client.post(f"/api/v1/findings/{fa}/feedback", json={"verdict": "false_positive"})
        client.post(f"/api/v1/findings/{fa}/feedback", json={"verdict": "accepted_risk"})
        p = client.get("/api/v1/feedback/precision").json()["rules"]
        assert len(p) == 1 and p[0]["rule_id"] == "weak-cipher-suite"
        assert p[0]["precision"] == 0.5
        assert p[0]["labels"] == 3
        exp = client.get("/api/v1/feedback/export?format=csv")
        assert exp.status_code == 200 and "false_positive" in exp.text
        assert "weak-cipher-suite" in exp.text
        js = client.get("/api/v1/feedback/export?format=json").json()
        assert len(js["labels"]) == 3
    finally:
        _clear()


def test_diagnostics_redacts_secrets_and_masks_addresses():
    maker = _setup()
    client = _client(maker, "org-a")
    try:
        r = client.get("/api/v1/diagnostics/bundle")
        assert r.status_code == 200, r.text
        import json
        blob = json.dumps(r.json())
        for leaked in ("cipherpost-dev-only-secret", "change-me"):
            assert leaked not in blob
        cfg = r.json()["config"]
        assert cfg["JWT_SECRET"] in ("set", "unset")
        assert "CIPHERPOST_JWT_SECRET" not in blob
        # non-admin cannot unmask addresses
        r = client.get("/api/v1/diagnostics/bundle?include_addresses=true")
        assert r.status_code == 403
    finally:
        _clear()
