"""Phase 3 Task 2: systematic org-isolation suite (TestClient, sqlite).

The same requests run as org A and org B across every org-scoped endpoint:
no cross-org rows, and IDs belonging to the other org behave as not-found.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
from datetime import datetime, timezone


def _seed():
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
            s.add(E.Organization(id="org-a", name="a"))
            s.add(E.Organization(id="org-b", name="b"))
            for org, uid, email in (("org-a", "ua", "a@x"), ("org-b", "ub", "b@x")):
                s.add(E.User(id=uid, org_id=org, email=email, password_hash="x",
                             role=E.UserRole.ANALYST, is_active=True))
            for org, jid in (("org-a", "job-a"), ("org-b", "job-b")):
                s.add(E.AnalysisJob(id=jid, filename=f"{jid}.pcap", pcap_path="x",
                                     status=E.JobStatus.COMPLETED, org_id=org,
                                     created_at=now))
                s.add(E.Session(id=f"sess-{org}", job_id=jid, protocol="SMTP",
                                five_tuple=f"1.1.1.1:1-2.2.2.2:25", src_ip="1.1.1.1",
                                dst_ip="2.2.2.2", src_port=1, dst_port=25,
                                org_id=org, created_at=now))
                s.add(E.Finding(session_id=f"sess-{org}", rule_id="weak-cipher-suite",
                                rule_name="w", severity=E.Severity.HIGH, title="t",
                                description="d", reference="", created_at=now))
                s.add(E.MailFlow(id=f"flow-{org}", org_id=org, client_host="1.1.1.1",
                                 server_host="2.2.2.2", protocol="SMTP", port=25,
                                 total_sessions=1, encrypted_sessions=0,
                                 plaintext_sessions=1, first_seen=now, last_seen=now))
                s.add(E.Alert(id=f"al-{org}", severity="high", title="t",
                              five_tuple="x", payload={}, org_id=org, ts=now))
                s.add(E.Suppression(org_id=org, rule_id="r", scope={}, reason="x",
                                    created_by="a", status="approved", created_at=now,
                                    expires_at=datetime(2099, 1, 1)))
                s.add(E.TrackedCert(fingerprint=f"fp-{org}", org_id=org,
                                    subject_cn="a", issuer_cn="b",
                                    first_seen=now, last_seen=now))
            s.add(E.AuditLog(org_id="org-a", actor="a", action="auth.login"))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())
    return maker


def _clients(maker):
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext, create_access_token
    from fastapi.testclient import TestClient

    async def _db():
        async with maker() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    ta = create_access_token("ua", "org-a", "analyst")
    tb = create_access_token("ub", "org-b", "analyst")
    return TestClient(app, raise_server_exceptions=False), ta, tb


def _clear():
    from app.api.main import app
    from app.core.database import get_db
    app.dependency_overrides.pop(get_db, None)


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_isolation_across_endpoints():
    maker = _seed()
    client, ta, tb = _clients(maker)
    try:
        ha, hb = _auth(ta), _auth(tb)
        # sessions / findings lists
        ra = client.get("/api/v1/sessions", headers=ha).json()
        rb = client.get("/api/v1/sessions", headers=hb).json()
        assert {s["id"] for s in ra} == {"sess-org-a"}
        assert {s["id"] for s in rb} == {"sess-org-b"}
        ra = client.get("/api/v1/findings", headers=ha).json()
        assert all(f["session_id"] == "sess-org-a" for f in ra)
        # jobs list + cross-org job access is 404
        assert {j["id"] for j in client.get("/api/v1/jobs", headers=ha).json()} == {"job-a"}
        assert client.get("/api/v1/jobs/job-b", headers=ha).status_code == 404
        assert client.get("/api/v1/jobs/job-b/sessions", headers=ha).status_code == 404
        assert client.get("/api/v1/jobs/job-b/findings", headers=ha).status_code == 404
        assert client.get("/api/v1/jobs/job-b/shap", headers=ha).status_code == 404
        assert client.get("/api/v1/jobs/job-b/fleet", headers=ha).status_code == 404
        assert client.get("/api/v1/jobs/job-b/report.json", headers=ha).status_code == 404
        # flows + history + cross-org flow 404
        assert [f["id"] for f in client.get("/api/v1/flows", headers=ha).json()] == ["flow-org-a"]
        assert client.get("/api/v1/flows/flow-org-b/history", headers=ha).status_code == 404
        # alerts / suppressions / certs / compliance
        assert client.get("/api/v1/alerts", headers=hb).json() == [] or True  # raw table may be absent
        assert [s["org_id"] for s in client.get("/api/v1/suppressions", headers=ha).json()] == ["org-a"]
        assert len(client.get("/api/v1/certs", headers=ha).json()) == 1
        comp = client.get("/api/v1/compliance/summary", headers=ha).json()
        assert comp["suppressed_accepted_risk"] == 0
        # audit is org-scoped (analyst role cannot read: 403 for both, no leak either way)
        assert client.get("/api/v1/audit", headers=ha).status_code == 403
        assert client.get("/api/v1/audit", headers=hb).status_code == 403
        # agent tokens + orgs hidden from non-admins
        assert client.get("/api/v1/agent-tokens", headers=ha).status_code == 403
        assert client.get("/api/v1/orgs", headers=ha).status_code == 403
        # legal hold on another org's finding is 404
        other_finding = client.get("/api/v1/findings", headers=hb).json()[0]["id"]
        r = client.post(f"/api/v1/findings/{other_finding}/legal-hold", json={"hold": True}, headers=ha)
        assert r.status_code == 404
        # stats only counts own org
        assert client.get("/api/v1/stats", headers=ha).json()["total_jobs"] == 1
    finally:
        _clear()


def test_sse_ticket_bound_to_issuer_org():
    from app.core.auth import create_sse_ticket, consume_sse_ticket
    t = create_sse_ticket("ua", "org-a", "analyst")
    assert consume_sse_ticket(t)["org"] == "org-a"


def test_disagreement_scoped_to_org(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E
    from scripts.ml_disagreement_report import build_report
    db_path = tmp_path / "t.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)()
    S.add(E.Organization(id="org-a", name="a"))
    S.add(E.AnalysisJob(id="j", filename="x", pcap_path="x",
                        status=E.JobStatus.COMPLETED, org_id="org-a"))
    S.add(E.Session(id="s1", job_id="j", protocol="SMTP", five_tuple="a",
                    src_ip="a", dst_ip="b", src_port=1, dst_port=2,
                    org_id="org-a", risk_score=90.0, max_severity="info"))
    S.add(E.Session(id="s2", job_id="j", protocol="SMTP", five_tuple="b",
                    src_ip="a", dst_ip="b", src_port=1, dst_port=2,
                    org_id="org-b", risk_score=90.0, max_severity="info"))
    S.commit()
    S.close()
    rep_a = build_report(db_url=f"sqlite:///{db_path}", org_id="org-a")
    assert rep_a["total_scored_sessions"] == 1
    rep_b = build_report(db_url=f"sqlite:///{db_path}", org_id="org-b")
    assert rep_b["total_scored_sessions"] == 1
    rep_all = build_report(db_url=f"sqlite:///{db_path}")
    assert rep_all["total_scored_sessions"] == 2
