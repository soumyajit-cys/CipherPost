"""
Track 1: auth unit tests — no DB server, no network.
Covers password hashing, JWT round-trip/tamper/expiry, API key handling,
role hierarchy, and the tenancy-ready data model (sqlite in-memory).
"""
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))


def test_password_hash_verify():
    from app.core.auth import hash_password, verify_password
    h = hash_password("correct-horse-123")
    assert verify_password("correct-horse-123", h)
    assert not verify_password("wrong", h)
    assert not verify_password("correct-horse-123", "garbage")
    # salts differ
    assert hash_password("x" * 12) != hash_password("x" * 12)


def test_jwt_roundtrip_and_tamper():
    from app.core.auth import create_access_token, decode_token
    tok = create_access_token("user-1", "org-1", "analyst", expires_in=60)
    claims = decode_token(tok)
    assert claims["sub"] == "user-1"
    assert claims["org"] == "org-1"
    assert claims["role"] == "analyst"
    # tampered payload rejected
    import base64, json
    h, p, s = tok.split(".")
    bad = base64.urlsafe_b64encode(json.dumps(
        {"sub": "admin", "org": "org-1", "role": "admin",
         "iat": 0, "exp": 9999999999}).encode()).rstrip(b"=").decode()
    try:
        decode_token(f"{h}.{bad}.{s}")
        assert False, "tampered token accepted"
    except ValueError:
        pass


def test_jwt_expiry():
    from app.core.auth import create_access_token, decode_token
    tok = create_access_token("u", "o", "auditor", expires_in=-1)
    try:
        decode_token(tok)
        assert False, "expired token accepted"
    except ValueError:
        pass


def test_api_key_format_and_hash():
    from app.core.auth import generate_api_key, hash_api_key
    raw, digest, prefix = generate_api_key()
    assert raw.startswith("cp_")
    assert hash_api_key(raw) == digest
    assert raw.startswith(prefix)
    r2, _, _ = generate_api_key()
    assert r2 != raw


def test_role_hierarchy():
    from app.core.auth import ROLE_ORDER
    assert ROLE_ORDER["auditor"] < ROLE_ORDER["analyst"] < ROLE_ORDER["admin"]


def test_tenancy_model_sqlite():
    """org_id columns exist and scope queries correctly (sqlite)."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E  # noqa: ensure models registered

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)()
    o1 = E.Organization(id="org-a", name="a")
    o2 = E.Organization(id="org-b", name="b")
    S.add_all([o1, o2])
    S.add(E.AnalysisJob(id="j1", filename="a.pcap", pcap_path="x",
                        status=E.JobStatus.COMPLETED, org_id="org-a"))
    S.add(E.AnalysisJob(id="j2", filename="b.pcap", pcap_path="y",
                        status=E.JobStatus.COMPLETED, org_id="org-b"))
    S.add(E.AnalysisJob(id="j3", filename="legacy.pcap", pcap_path="z",
                        status=E.JobStatus.COMPLETED, org_id=None))
    S.commit()
    mine = S.execute(select(E.AnalysisJob).where(
        E.AnalysisJob.org_id == "org-a")).scalars().all()
    assert [j.id for j in mine] == ["j1"]
    # audit + users + keys tables exist
    S.add(E.AuditLog(org_id="org-a", actor="admin@x", action="auth.login"))
    S.commit()
    assert S.query(E.AuditLog).count() == 1
    S.close()
