"""Label export + manifest hygiene tests (Task 7)."""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from app.core.database import Base
import app.models.entities as E

_spec = importlib.util.spec_from_file_location(
    "export_labels", Path(__file__).resolve().parents[2] / "scripts" / "export_labels.py")
el = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(el)

UTC = timezone.utc
NOW = datetime(2026, 10, 25, 9, 0, tzinfo=UTC)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    from sqlalchemy.orm import Session as OrmSession
    with OrmSession(eng) as s:
        s.add(E.Organization(id="org-a", name="A"))
        s.add(E.Session(id="sess-1", job_id="live", protocol="SMTP",
                        five_tuple="f", src_ip="a", dst_ip="b",
                        src_port=1, dst_port=2, tls_version="TLS1.2",
                        ja4="t12d_x", org_id="org-a", created_at=NOW))
        s.add_all([
            E.FindingFeedback(org_id="org-a", finding_id=1, rule_id="weak-cipher-suite",
                              session_id="sess-1", verdict="confirmed",
                              comment="[triage:bug] rule fired on valid config",
                              created_by="ana@pilot.example", created_at=NOW),
            E.FindingFeedback(org_id="org-a", finding_id=2, rule_id="tls-version-tls1-0",
                              session_id="sess-1", verdict="false_positive",
                              comment="[triage:noise] legacy host, suppressed",
                              created_by="ana@pilot.example", created_at=NOW),
            E.FindingFeedback(org_id="org-a", finding_id=3, rule_id="weak-cipher-suite",
                              session_id="sess-1", verdict="accepted_risk",
                              comment="no triage prefix here",
                              created_by="boss@pilot.example", created_at=NOW),
        ])
        s.commit()
    return eng


def test_export_format_matches_ml_pipeline(engine):
    data = el.export_labels(engine)
    rows = data["analyst"]["rows"]
    # accepted_risk excluded; confirmed -> y=1, false_positive -> y=0
    assert sorted(r["y"] for r in rows) == [0, 1]
    assert all(r["source"] == "analyst" for r in rows)
    assert all(set(r) == {"session_id", "y", "source"} for r in rows)
    # rules rows in a SEPARATE section, never merged into analyst rows
    assert all(r["source"] == "rules" for r in data["rules"]["rows"])
    assert data["analyst"]["rows"] != data["rules"]["rows"]


def test_provenance_fields_present(engine):
    data = el.export_labels(engine)
    prov = data["analyst"]["provenance"]
    by_verdict = {p["verdict"]: p for p in prov}
    p = by_verdict["confirmed"]
    assert p["who"] == "ana@pilot.example"
    assert p["when"].startswith("2026-10-25")
    assert p["rule_version"] == data["tool_version"]
    assert p["session_id"] == "sess-1"
    assert p["verdict"] == "confirmed"
    assert p["y"] == 1
    # triage category parsed out of the comment; comment returned without prefix
    assert p["triage_category"] == "bug"
    assert p["comment"] == "rule fired on valid config"
    assert by_verdict["false_positive"]["triage_category"] == "noise"
    # accepted_risk row still carries provenance (with y=None)
    accepted = [p for p in prov if p["y"] is None]
    assert len(accepted) == 1 and accepted[0]["verdict"] == "accepted_risk"
    assert accepted[0]["who"] == "boss@pilot.example"
    assert accepted[0]["triage_category"] is None  # no prefix in comment


def test_triage_parse():
    assert el.parse_triage("[triage:noise] hi") == "noise"
    assert el.parse_triage("[triage:expected-behavior] x") == "expected-behavior"
    assert el.parse_triage("no prefix") is None
    assert el.parse_triage(None) is None
    assert el.parse_triage("[triage:bogus] x") == "bogus"  # parser is lenient;
    # the API endpoint is the validator (400 on unknown categories)


def test_org_scoping(engine):
    from sqlalchemy.orm import Session as OrmSession
    with OrmSession(engine) as s:
        s.add(E.Organization(id="org-b", name="B"))
        s.add(E.FindingFeedback(org_id="org-b", finding_id=9, rule_id="r",
                                session_id="sess-2", verdict="confirmed",
                                comment="", created_by="b@x", created_at=NOW))
        s.commit()
    data = el.export_labels(engine, org_id="org-a")
    assert all(p["who"] != "b@x" for p in data["analyst"]["provenance"])
    all_rows = el.export_labels(engine)
    assert len(all_rows["analyst"]["rows"]) == 3


# --- manifest hygiene (permission check) ---------------------------------------

def _entry(**over):
    base = {"pcap": "x.pcap", "source": "lab postfix", "license": "CC0",
            "data_class": "lab", "expected_findings": []}
    base.update(over)
    return base


def test_manifest_check_lab_entry_ok():
    errors, warnings = el.check_manifest({"captures": [_entry()]})
    assert errors == [] and warnings == []


def test_manifest_check_requires_source_and_license():
    errors, _ = el.check_manifest({"captures": [_entry(source="", license="")]})
    assert any("'source'" in e for e in errors)
    assert any("'license'" in e for e in errors)


def test_manifest_check_live_run_requires_authorization_permission_pseudonymized():
    errors, _ = el.check_manifest({"captures": [
        _entry(data_class="live-run", source="30-day run", license="internal")]})
    assert any("'authorization'" in e for e in errors)
    assert any("'permission'" in e for e in errors)
    assert any("pseudonymized" in e for e in errors)
    ok, _ = el.check_manifest({"captures": [
        _entry(data_class="live-run", source="30-day run", license="internal",
               authorization="owner's own server, 2026-10",
               permission="owner-approved for tests/real",
               pseudonymized=True)]})
    assert ok == []


def test_manifest_check_pilot_same_rules():
    errors, _ = el.check_manifest({"captures": [
        _entry(data_class="pilot", license="CC0", source="pilot org",
               authorization="signed agreement", pseudonymized=True)]})
    assert any("'permission'" in e for e in errors)


def test_manifest_check_unknown_data_class_and_legacy_warn():
    errors, warnings = el.check_manifest({"captures": [_entry(data_class="wat")]})
    assert any("unknown data_class" in e for e in errors)
    legacy = {k: v for k, v in _entry().items() if k != "data_class"}
    errors, warnings = el.check_manifest({"captures": [legacy]})
    assert errors == [] and any("data_class" in w for w in warnings)


def test_check_manifest_cli_on_real_manifest():
    """The repo's committed lab manifest must pass (legacy entries warn only)."""
    manifest = Path(__file__).resolve().parents[2] / "tests" / "real" / "manifest.json"
    data = json.loads(manifest.read_text())
    errors, warnings = el.check_manifest(data)
    assert errors == [], errors
    assert len(warnings) >= 1  # legacy lab entries asked to add data_class


def test_export_cli_roundtrip(engine, tmp_path, monkeypatch):
    db_file = tmp_path / "l.db"
    e2 = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(e2)
    with engine.connect() as src, e2.begin() as dst:
        for tbl in ("organizations", "sessions", "finding_feedback"):
            for row in src.execute(
                    __import__("sqlalchemy").text(f"SELECT * FROM {tbl}")).mappings():
                cols = list(row.keys())
                dst.execute(
                    __import__("sqlalchemy").text(
                        f"INSERT INTO {tbl} ({', '.join(cols)}) VALUES "
                        f"({', '.join(':' + c for c in cols)})"),
                    {c: row[c] for c in cols})
    out = tmp_path / "labels.json"
    monkeypatch.setattr("app.core.config.settings.DATABASE_URL_SYNC",
                        f"sqlite:///{db_file}")
    rc = el.main(["--out", str(out)])
    assert rc == 0 and out.exists()
    data = json.loads(out.read_text())
    assert len(data["analyst"]["rows"]) == 2  # accepted_risk excluded
    assert data["analyst"]["rows"] != data["rules"]["rows"]
