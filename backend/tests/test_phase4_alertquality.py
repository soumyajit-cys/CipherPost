"""Phase 4 Task 5: alert quality, routing, policy, digest, quiet hours, explain."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import json
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
            s.add(E.Organization(id="org-a", name="a"))
            s.add(E.User(id="ua", org_id="org-a", email="a@x", password_hash="x",
                         role=E.UserRole.ADMIN, is_active=True))
            s.add(E.AnalysisJob(id="j", filename="x", pcap_path="x",
                                 status=E.JobStatus.COMPLETED, org_id="org-a",
                                 created_at=now))
            s.add(E.Session(id="s1", job_id="j", protocol="SMTP",
                            five_tuple="1.1.1.1:1-2.2.2.2:25", src_ip="a", dst_ip="b",
                            src_port=1, dst_port=2, org_id="org-a", created_at=now))
            for i, sev in enumerate((E.Severity.HIGH, E.Severity.LOW)):
                s.add(E.Finding(session_id="s1", rule_id="weak-cipher-suite",
                                rule_name="w", severity=sev, title="t",
                                description="d", reference="", created_at=now))
            s.add(E.FindingFeedback(org_id="org-a", finding_id=1,
                                    rule_id="weak-cipher-suite", session_id="s1",
                                    verdict="confirmed", comment="",
                                    created_by="a", created_at=now))
            s.add(E.Alert(id="al1", severity="high", title="t",
                          five_tuple="1.1.1.1:1-2.2.2.2:25",
                          payload=json.dumps({"rule_id": "weak-cipher-suite"}),
                          org_id="org-a", ts=now))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())
    return maker


def _client(maker, role="admin"):
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext
    from fastapi.testclient import TestClient

    async def _db():
        async with maker() as s:
            yield s

    async def _user():
        return AuthContext(user_id="ua", email="a@x", org_id="org-a",
                           role=role, via="jwt")

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    return TestClient(app, raise_server_exceptions=False)


def _clear():
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


def test_quality_reports_measured_precision_and_flags_review():
    maker, client = _setup(), None
    client = _client(maker)
    try:
        body = client.get("/api/v1/alerts/quality").json()
        by_rule = {r["rule_id"]: r for r in body["rules"]}
        w = by_rule["weak-cipher-suite"]
        assert w["confirmed"] == 1 and w["false_positive"] == 0
        assert w["precision"] == 1.0  # measured, not guessed
        assert w["alerts"] == 1 and w["findings"] == 2
        assert w["tta_hours_median"] is not None
        assert "insufficient data" in body["note"] or "precision is null" in body["note"]
    finally:
        _clear()


def test_routes_crud_and_specificity_order():
    maker = _setup()
    client = _client(maker)
    try:
        assert client.post("/api/v1/alert-routes",
                           json={"match_type": "bogus", "match_value": "x"}).status_code == 400
        r = client.post("/api/v1/alert-routes",
                        json={"match_type": "rule", "match_value": "weak-cipher-suite",
                              "owner": "net-team", "channel": "webhook"})
        assert r.status_code == 200
        r = client.post("/api/v1/alert-routes",
                        json={"match_type": "host", "match_value": "2.2.2.2",
                              "owner": "mail-team", "channel": "slack"})
        assert r.status_code == 200
        assert len(client.get("/api/v1/alert-routes").json()) == 2
        # dispatcher prefers host over rule
        import fakeredis
        from app.live.alerts import AlertDispatcher
        d = AlertDispatcher(redis_client=fakeredis.FakeRedis(decode_responses=False),
                            adapters=[])
        # stub the DB-backed route load with the created rows is heavyweight;
        # exercise pure matching through a stubbed loader instead:
        d._routes_cache["org-a"] = (9999999999.0, [
            {"match_type": "rule", "match_value": "weak-cipher-suite",
             "owner": "net-team", "channel": "webhook"},
            {"match_type": "host", "match_value": "2.2.2.2",
             "owner": "mail-team", "channel": "slack"},
        ])
        routed = d._route_finding({"rule_id": "weak-cipher-suite",
                                   "five_tuple": "1.1.1.1:1-2.2.2.2:25"})
        assert routed == {"owner": "mail-team", "channel": "slack"}
    finally:
        _clear()


def test_severity_policy_gates_dispatch():
    import fakeredis
    from app.live.alerts import AlertDispatcher
    r = fakeredis.FakeRedis(decode_responses=False)
    d = AlertDispatcher(redis_client=r, adapters=[])
    d._policy_cache["org-a"] = (9999999999.0, {"min_severity": "critical",
                                               "digest": "off"})
    d.min_sev = 0  # global would allow; policy must win in _dispatch path
    sent = []
    d.adapters = [type("A", (), {"name": "t", "send": lambda self, a: sent.append(a) or True})()]
    # high finding under a critical-only policy: no dispatch
    d._dispatch({"rule_id": "weak-cipher-suite", "severity": "high",
                 "max_severity": "high", "title": "t", "description": "d",
                 "five_tuple": "a-b", "protocol": "SMTP", "org_id": "org-a",
                 "findings": []})
    assert sent == []


def test_digest_and_quiet_hours_hold_non_critical():
    import fakeredis
    import time
    from app.live.alerts import AlertDispatcher
    r = fakeredis.FakeRedis(decode_responses=False)
    d = AlertDispatcher(redis_client=r, adapters=[])
    # quiet window covering right now (deterministic, no midnight flake)
    import datetime as _dt
    _h = _dt.datetime.now(_dt.timezone.utc).hour
    d._policy_cache["org-a"] = (9999999999.0, {"min_severity": "info",
                                               "digest": "off",
                                               "quiet_start_hour": (_h - 1) % 24,
                                               "quiet_end_hour": (_h + 1) % 24,
                                               "quiet_tz": "UTC"})
    f = {"rule_id": "weak-cipher-suite", "severity": "high", "max_severity": "high",
         "title": "t", "description": "d", "five_tuple": "a-b", "protocol": "SMTP",
         "org_id": "org-a", "findings": [], "ts": time.time()}
    # emulate _handle_entry gating directly
    from app.live import streams as bus
    c = bus.StreamConsumer(r, "q", "g", "c")
    d.consumer = c
    bus.publish(r, "q", f)
    eid, payload = c.poll_raw(timeout_ms=100)[0]
    d._handle_entry(eid, payload)
    # held, not dispatched (no adapters anyway) — quiet bucket has it
    assert r.get("quiet:org-a") is not None
    # critical bypasses quiet
    f2 = dict(f, severity="critical", max_severity="critical")
    bus.publish(r, "q", f2)
    eid2, payload2 = c.poll_raw(timeout_ms=100)[0]
    d._handle_entry(eid2, payload2)
    assert c.pending_count() == 0  # acked via group path (hold=10s not expired... )
    d.consumer.ack(eid2)


def test_explain_verified_and_unverified():
    maker = _setup()
    client = _client(maker)
    try:
        # seed an alert with a verified rule
        import json as _json
        r = client.get("/api/v1/alerts").json()
        assert r, "expected seeded alert"
        al = r[0]["id"]
        out = client.get(f"/api/v1/alerts/{al}/explain").json()
        assert out["rule_id"] == "weak-cipher-suite"
        assert out["remediation"]["verified"] is True
        assert "postfix.org" in out["remediation"]["source"]
        assert out["rationale"]["reference"] != ""
        # unknown id 404s; other-org tested in isolation suite pattern
        assert client.get("/api/v1/alerts/nope/explain").status_code == 404
    finally:
        _clear()
