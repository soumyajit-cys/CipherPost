"""
Track 2: proactive detection + compliance mapping tests (no DB server).
"""
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))


def _memdb():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities  # noqa: register
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _fake_cert(der: bytes, cn="mail.example.com", days_left=10, ca=False):
    from types import SimpleNamespace
    now = datetime.utcnow()
    return SimpleNamespace(
        der=der, is_ca=ca, subject_cn=cn, issuer_cn="Test CA",
        subject_alt_names=[cn], not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=days_left),
        pubkey_alg="RSA", pubkey_bits=2048, signature_alg="sha256WithRSA",
        is_self_signed=False,
    )


def _fake_sa(certs):
    from types import SimpleNamespace
    return SimpleNamespace(certs=certs, chain_result="ok")


def test_cert_tracking_and_forecast():
    from app.proactive.certs import track_session_certs, find_expiring
    db = _memdb()
    n = track_session_certs(_fake_sa([_fake_cert(b"leaf-der-1", days_left=5)]), "org-a", db)
    db.commit()
    assert n == 1
    # re-observe bumps count, doesn't duplicate
    n = track_session_certs(_fake_sa([_fake_cert(b"leaf-der-1", days_left=5)]), "org-a", db)
    db.commit()
    assert n == 1
    from app.models.entities import TrackedCert
    assert db.query(TrackedCert).count() == 1
    assert db.query(TrackedCert).first().seen_count == 2
    # forecast catches it inside 30d window
    rows = find_expiring("org-a", 30, db)
    assert len(rows) == 1
    # but not inside a 1-day window
    assert find_expiring("org-a", 1, db) == []
    # CA certs are not inventoried
    track_session_certs(_fake_sa([_fake_cert(b"ca-der", ca=True)]), "org-a", db)
    db.commit()
    assert db.query(TrackedCert).count() == 1
    db.close()


def test_compliance_mapping_known_rules():
    from app.proactive.compliance import compliance_for, FRAMEWORKS
    tags = compliance_for("expired-certificate")
    fw = {t["framework"] for t in tags}
    assert "PCI-DSS-4.0" in fw and "ISO-27001-2022" in fw
    # wildcard rule ids
    assert compliance_for("tls-version-tls1-0")
    assert compliance_for("bogus-rule-id") == []
    assert set(FRAMEWORKS) >= {"PCI-DSS-4.0", "ISO-27001-2022", "NIST-CSF-2.0", "OWASP-TLS", "CERT-In"}


def test_compliance_summary_groups():
    from app.proactive.compliance import summary_for_findings
    out = summary_for_findings([
        {"rule_id": "expired-certificate", "severity": "high"},
        {"rule_id": "rc4-cipher", "severity": "critical"},
        {"rule_id": "bogus", "severity": "info"},
    ])
    assert out["unmapped_findings"] == 1
    assert out["groups"]
    pci = summary_for_findings([
        {"rule_id": "expired-certificate", "severity": "high"},
    ], framework="PCI-DSS-4.0")
    assert all(g["framework"] == "PCI-DSS-4.0" for g in pci["groups"])
    try:
        summary_for_findings([], framework="NOPE")
        assert False
    except KeyError:
        pass


def test_mta_sts_stub_is_honest():
    from app.proactive.mta_sts import check_domain, mismatch_for_session
    r = check_domain("example.com")
    assert r["status"] == "not-checked"
    assert r["mta_sts"]["supported"] is False
    assert mismatch_for_session("example.com", False) is None
    assert check_domain("")["status"] == "invalid-domain"
