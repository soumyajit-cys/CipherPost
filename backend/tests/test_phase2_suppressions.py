"""Phase 2 Task 3: suppressions (pure matching + sqlite org isolation)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone, timedelta


def _sup(rule="weak-cipher-suite", scope=None, status="approved", days=30, org="org-a"):
    from types import SimpleNamespace
    now = datetime.now(timezone.utc)
    return SimpleNamespace(id=1, org_id=org, rule_id=rule, scope=scope or {},
                           status=status, expires_at=now + timedelta(days=days))


def test_cidr_scope_matching():
    from app.proactive.suppressions import scope_matches
    scope = {"cidrs": ["10.0.0.0/8"]}
    assert scope_matches(scope, {"five_tuple": "10.1.2.3:5000-9.9.9.9:25"}) is True
    assert scope_matches(scope, {"five_tuple": "192.168.1.1:5000-9.9.9.9:25"}) is False
    # AND semantics: cidr + port must both match
    scope2 = {"cidrs": ["10.0.0.0/8"], "ports": [25]}
    assert scope_matches(scope2, {"five_tuple": "10.1.2.3:5000-9.9.9.9:25"}) is True
    assert scope_matches(scope2, {"five_tuple": "10.1.2.3:5000-9.9.9.9:587"}) is False


def test_wildcard_domain_matching():
    from app.proactive.suppressions import scope_matches
    scope = {"domains": ["*.legacy.example"]}
    assert scope_matches(scope, {"sni": "mail.legacy.example"}) is True
    assert scope_matches(scope, {"sni": "mail.example.com"}) is False


def test_expiry_enforced():
    from app.proactive.suppressions import match_suppression, scope_matches
    live = _sup(days=30)
    dead = _sup(days=-1)
    assert match_suppression("weak-cipher-suite", {"five_tuple": "a:1-b:2"}, [live]) is live
    assert match_suppression("weak-cipher-suite", {"five_tuple": "a:1-b:2"}, [dead]) is None
    pending = _sup(status="pending")
    assert match_suppression("weak-cipher-suite", {"five_tuple": "a:1-b:2"}, [pending]) is None


def test_org_isolation_sqlite():
    """Suppressions are always queried per-org; other orgs never match."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)()
    S.add(E.Organization(id="org-a", name="a"))
    S.add(E.Organization(id="org-b", name="b"))
    now = datetime.now(timezone.utc)
    S.add(E.Suppression(org_id="org-a", rule_id="weak-cipher-suite", scope={},
                        reason="legacy", created_by="admin@x", status="approved",
                        created_at=now, expires_at=now + timedelta(days=30)))
    S.commit()
    from app.proactive.suppressions import match_suppression, filter_active
    rows_a = S.execute(select(E.Suppression).where(
        E.Suppression.org_id == "org-a")).scalars().all()
    rows_b = S.execute(select(E.Suppression).where(
        E.Suppression.org_id == "org-b")).scalars().all()
    assert len(rows_a) == 1 and len(rows_b) == 0
    assert match_suppression("weak-cipher-suite", {"five_tuple": "a:1-b:2"},
                             filter_active(rows_a)) is not None
    assert match_suppression("weak-cipher-suite", {"five_tuple": "a:1-b:2"},
                             filter_active(rows_b)) is None
    # audit table exists for the trail (written by API, verified in API test)
    S.add(E.AuditLog(org_id="org-a", actor="admin@x", action="suppression.create"))
    S.commit()
    assert S.query(E.AuditLog).filter_by(action="suppression.create").count() == 1
    S.close()
