"""Phase 2 Task 6: mail-flow aggregation, regression, org isolation (sqlite)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone


def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E  # noqa
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)(), E


def _payload(ft="10.0.0.1:5000-10.0.0.2:25", proto="SMTP"):
    return {"five_tuple": ft, "protocol": proto}


def test_aggregation_counts_and_versions():
    from app.live.flows import update_flow
    S, E = _db()
    S.add(E.Organization(id="o", name="default"))
    S.commit()
    now = datetime.now(timezone.utc)
    for v in ("TLS 1.3", "TLS 1.3", "TLS 1.2"):
        update_flow(S, "o", _payload(), v, "CIPHER", True, seen_at=now)
    S.commit()
    f = S.query(E.MailFlow).one()
    assert f.total_sessions == 3
    assert f.encrypted_sessions == 3 and f.plaintext_sessions == 0
    assert f.versions["TLS 1.3"] == 2 and f.best_version == "TLS 1.3"
    assert f.client_host == "10.0.0.1" and f.server_host == "10.0.0.2"
    S.close()


def test_regression_plaintext_after_encrypted():
    from app.live.flows import update_flow
    S, E = _db()
    S.add(E.Organization(id="o", name="default"))
    S.commit()
    now = datetime.now(timezone.utc)
    for _ in range(3):
        update_flow(S, "o", _payload(), "TLS 1.3", "C", True, seen_at=now)
    S.commit()
    _, reg = update_flow(S, "o", _payload(), None, None, False, seen_at=now)
    assert reg is not None and reg["rule_id"] == "transport-regression"
    assert reg["severity"] == "high"
    S.close()


def test_regression_version_downgrade_and_no_false_positive():
    from app.live.flows import update_flow
    S, E = _db()
    S.add(E.Organization(id="o", name="default"))
    S.commit()
    now = datetime.now(timezone.utc)
    for _ in range(3):
        update_flow(S, "o", _payload(), "TLS 1.3", "C", True, seen_at=now)
    S.commit()
    _, reg = update_flow(S, "o", _payload(), "TLS 1.0", "C", True, seen_at=now)
    assert reg is not None and "TLS 1.3" in reg["title"] and "TLS 1.0" in reg["title"]
    # upgrade is not a regression; tiny history (<3) never fires
    S2, _ = _db()
    S2.add(E.Organization(id="o", name="default"))
    S2.commit()
    update_flow(S2, "o", _payload(), "TLS 1.2", "C", True, seen_at=now)
    _, reg2 = update_flow(S2, "o", _payload(), "TLS 1.3", "C", True, seen_at=now)
    assert reg2 is None
    S.close(); S2.close()


def test_org_isolation():
    from app.live.flows import update_flow, flow_id
    S, E = _db()
    S.add(E.Organization(id="oa", name="a"))
    S.add(E.Organization(id="ob", name="b"))
    S.commit()
    now = datetime.now(timezone.utc)
    update_flow(S, "oa", _payload(), "TLS 1.3", "C", True, seen_at=now)
    update_flow(S, "ob", _payload(), "TLS 1.3", "C", True, seen_at=now)
    S.commit()
    assert S.query(E.MailFlow).count() == 2
    assert flow_id("oa", "x", "y", "SMTP", 25) != flow_id("ob", "x", "y", "SMTP", 25)
    S.close()
