"""Issue-bundle tests (Task 4): redaction guarantees on synthetic data.

Proves that with default settings the bundle contains no secrets and no
unmasked addresses, reuses the diagnostics-bundle redaction helpers, and
only attaches raw frames behind --include-pcap.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import importlib.util

import pytest
from sqlalchemy import create_engine, text

from app.core.database import Base
import app.models.entities as E

_spec = importlib.util.spec_from_file_location(
    "export_issue_bundle",
    Path(__file__).resolve().parents[2] / "scripts" / "export_issue_bundle.py")
ib = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ib)

UTC = timezone.utc
NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    from sqlalchemy.orm import Session as OrmSession
    with OrmSession(eng) as s:
        s.add(E.Organization(id="org-a", name="A"))
        s.add(E.Session(
            id="sess-1", job_id="live", protocol="SMTP",
            five_tuple="203.0.113.7:40000->198.51.100.9:587",
            src_ip="203.0.113.7", dst_ip="198.51.100.9",
            src_port=40000, dst_port=587, is_starttls=False,
            tls_version="TLS1.2",
            negotiated_cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ja4="t12d_abc", org_id="org-a",
            details={"raw_refs": []}, created_at=NOW))
        s.add(E.Finding(
            session_id="sess-1", rule_id="weak-cipher-suite",
            rule_name="Weak cipher suite", severity=E.Severity.HIGH,
            title="t", description="d", reference="r",
            evidence={"server": "198.51.100.9", "note": "3DES offered"},
            created_at=NOW))
        s.commit()
    return eng


def test_default_bundle_masks_addresses_and_has_no_secrets(engine):
    bundle, err = ib.build_bundle(engine, finding_id=1, session_id=None)
    assert err == ""
    blob = json.dumps(bundle)
    # full addresses must NOT appear anywhere in default output
    assert "203.0.113.7" not in blob and "198.51.100.9" not in blob
    # masked form (first two octets) must appear
    assert "203.0.x.x" in blob and "198.51.x.x" in blob
    # evidence inside the finding is masked too
    assert bundle["finding"]["evidence"]["server"] == "198.51.x.x"


def test_bundle_reuses_diagnostics_redacted_config(engine, monkeypatch):
    from app.core.config import Settings
    s = Settings(JWT_SECRET="super-secret-value-0123456789abcdef",
                 ADMIN_PASSWORD="super-secret-password",
                 ADMIN_EMAIL="owner@example.com")
    import app.api.main as apimain
    monkeypatch.setattr(apimain, "settings", s, raising=False)
    bundle, err = ib.build_bundle(engine, finding_id=1, session_id=None)
    assert err == ""
    blob = json.dumps(bundle)
    assert "super-secret-value" not in blob and "super-secret-password" not in blob
    # diagnostics helper marks secret fields set/unset
    assert bundle["config_redacted"]["JWT_SECRET"] == "set"
    assert bundle["config_redacted"]["ADMIN_PASSWORD"] == "set"


def test_pcap_only_behind_explicit_flag(engine):
    _, err = ib.build_bundle(engine, session_id="sess-1", include_pcap=False)
    assert err == ""
    bundle, _ = ib.build_bundle(engine, session_id="sess-1", include_pcap=False)
    assert bundle["raw_slice"]["included"] is False
    assert "--include-pcap" in bundle["raw_slice"]["reason"]


def test_pcap_slice_with_purged_refs_reports_honestly(engine, tmp_path):
    # refs point at a segment file that does not exist -> honest 'purged'
    with engine.begin() as c:
        c.execute(text("UPDATE sessions SET details = :d WHERE id='sess-1'"),
                  {"d": json.dumps({"raw_refs": [["cap-123.seg", 0, 64]]})})
    bundle, _ = ib.build_bundle(engine, session_id="sess-1", include_pcap=True,
                                raw_dir=str(tmp_path))
    assert bundle["raw_slice"]["included"] is False
    assert "purged" in bundle["raw_slice"]["reason"] or "unreadable" in bundle["raw_slice"]["reason"]


def test_pcap_slice_includes_real_frames(engine, tmp_path):
    # create a raw segment matching RollingRawStore format with one Ethernet frame
    from app.live.retention import RollingRawStore
    store = RollingRawStore(tmp_path, retention_seconds=3600, segment_seconds=300)
    eth = bytes.fromhex("ffffffffffff0800200aaabb0800") + b"\x00" * 20
    ref = store.write(1729771200.0, eth)
    store.stop()
    with engine.begin() as c:
        c.execute(text("UPDATE sessions SET details = :d WHERE id='sess-1'"),
                  {"d": json.dumps({"raw_refs": [list(ref)]})})
    bundle, _ = ib.build_bundle(engine, session_id="sess-1", include_pcap=True,
                                raw_dir=str(tmp_path))
    rs = bundle["raw_slice"]
    assert rs["included"] is True and rs["frames_decoded"] >= 1
    import base64
    assert base64.b64decode(rs["pcap_b64"])[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")


def test_not_found_and_cli_exit_codes(engine, tmp_path):
    _, err = ib.build_bundle(engine, finding_id=999, session_id=None)
    assert err == "not-found"
    db_file = tmp_path / "b.db"
    e2 = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(e2)
    # copy fixture rows
    with engine.begin() as src, e2.begin() as dst:
        for tbl in ("organizations", "sessions", "findings"):
            for row in src.execute(text(f"SELECT * FROM {tbl}")).mappings():
                cols = ", ".join(row.keys())
                vals = [row[k] for k in row.keys()]
                dst.execute(text(f"INSERT INTO {tbl} ({cols}) VALUES "
                                 f"({', '.join(':' + str(i) for i in range(len(vals)))})"),
                            {str(i): v for i, v in enumerate(vals)})
    out = tmp_path / "bundle.json"
    rc = ib.main(["--finding", "1", "--db-url", f"sqlite:///{db_file}", "--out", str(out)])
    assert rc == 0 and out.exists()
    blob = out.read_text()
    assert "203.0.113.7" not in blob and "198.51.100.9" not in blob
    rc_missing = ib.main(["--finding", "999", "--db-url", f"sqlite:///{db_file}"])
    assert rc_missing == 1
