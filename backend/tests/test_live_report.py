"""Live report tests (Task 3): synthetic SQLite fixtures, no Redis, no server.

Covers: normal day, capture gap (zero-session hours), dead-letter spike
(injected health), org isolation, and count agreement with direct SQL.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from app.core.database import Base
import app.models.entities as E

_spec = importlib.util.spec_from_file_location(
    "live_report", Path(__file__).resolve().parents[2] / "scripts" / "live_report.py")
lr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lr)


UTC = timezone.utc
DAY = datetime(2026, 10, 24, tzinfo=UTC)          # window: 2026-10-24 00:00 -> 2026-10-25
START = DAY
END = DAY + timedelta(days=1)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    with eng.begin() as c:
        c.execute(text("INSERT INTO organizations (id, name, created_at) VALUES "
                       "('org-a', 'A', CURRENT_TIMESTAMP), ('org-b', 'B', CURRENT_TIMESTAMP)"))
    return eng


def _add_session(eng, i, org="org-a", when=None, tls="TLS1.2", cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                 fp="t12d010300_a17193ba21fd_550742449778", flow=None, protocol="SMTP"):
    when = when or (START + timedelta(hours=3 + (i // 2), minutes=i % 60))
    from sqlalchemy.orm import Session as OrmSession
    with OrmSession(eng) as s:
        s.add(E.Session(
            id=f"s-{org}-{i}", job_id="live", protocol=protocol,
            five_tuple=flow or f"10.0.0.{i % 5}:1000->10.0.0.9:587",
            src_ip="10.0.0.1", dst_ip="10.0.0.9", src_port=1000, dst_port=587,
            tls_version=tls, negotiated_cipher=cipher, ja4=fp,
            org_id=org, created_at=when))
        s.commit()


def _add_finding(eng, sess_id, rule="weak-cipher-suite", sev="high", when=None):
    from sqlalchemy.orm import Session as OrmSession
    with OrmSession(eng) as s:
        s.add(E.Finding(session_id=sess_id, rule_id=rule, rule_name=rule,
                        severity=E.Severity(sev), title="t", description="d",
                        reference="r", created_at=when or START + timedelta(hours=4)))
        s.commit()


def test_normal_day_metrics_and_sql_agreement(engine):
    for i in range(6):
        _add_session(engine, i, tls="TLS1.2" if i % 2 else "TLS1.3")
    _add_finding(engine, "s-org-a-0", rule="weak-cipher-suite", sev="high")
    _add_finding(engine, "s-org-a-1", rule="untrusted-certificate-chain", sev="medium")
    with engine.begin() as c:
        c.execute(text("INSERT INTO finding_feedback (org_id, finding_id, rule_id, "
                       "session_id, verdict, comment, created_by, created_at) VALUES "
                       "('org-a', 1, 'weak-cipher-suite', 's-org-a-0', 'false_positive', "
                       "'', 'a@x', :t)"),
                  {"t": START + timedelta(hours=5)})

    r = lr.compute_report(engine, "org-a", START, END, health=None)
    # direct-SQL cross-check
    with engine.connect() as conn:
        n = conn.execute(text(
            "SELECT COUNT(*) FROM sessions WHERE created_at >= :s AND created_at < :e "
            "AND org_id='org-a'"), {"s": START, "e": END}).scalar()
        n_enc = conn.execute(text(
            "SELECT COUNT(*) FROM sessions WHERE created_at >= :s AND created_at < :e "
            "AND org_id='org-a' AND tls_version IS NOT NULL"), {"s": START, "e": END}).scalar()
    assert r["sessions"]["total"] == n == 6
    assert r["sessions"]["encrypted"] == n_enc == 6
    assert r["sessions"]["plaintext"] == 0
    assert r["sessions"]["encrypted_share"] == 1.0
    assert r["sessions"]["per_protocol"] == {"SMTP": 6}
    assert set(r["sessions"]["tls_versions"]) == {"TLS1.2", "TLS1.3"}
    assert r["findings"]["by_rule"] == {"weak-cipher-suite": 1,
                                        "untrusted-certificate-chain": 1}
    assert r["findings"]["by_severity"] == {"high": 1, "medium": 1}
    assert r["feedback"] == {"false_positive": 1}
    # sessions at hours 03-05 only: the other 21 hours of the day are gaps
    assert len(r["gaps_zero_session_hours"]) == 21
    assert "2026-10-24 03" not in r["gaps_zero_session_hours"]
    assert r["flags"] == [{"kind": "coverage-gap", "detail": r["flags"][0]["detail"]}]


def test_capture_gap_flags_zero_session_hours(engine):
    # one session at 03:00 only -> 23 other hours are gaps; also empty window
    # after a populated previous window -> capture-stop flag
    _add_session(engine, 0, when=START + timedelta(hours=3))
    for i in range(5):  # previous day busy (distinct ids)
        _add_session(engine, 10 + i, when=START - timedelta(hours=2 + i))
    r = lr.compute_report(engine, "org-a", START, END, health=None)
    assert len(r["gaps_zero_session_hours"]) == 23
    assert r["gaps_zero_session_hours"][0] == "2026-10-24 00"
    kinds = {f["kind"] for f in r["flags"]}
    assert "coverage-gap" in kinds
    assert "capture-stop-suspected" in kinds or "sessions-drop" in kinds


def test_dead_letter_spike_via_injected_health(engine):
    _add_session(engine, 0)
    health = {"consumer_lag": 1500, "dlq_depth": 7, "capture_drops": {}}
    r = lr.compute_report(engine, "org-a", START, END, health=health)
    kinds = {f["kind"] for f in r["flags"]}
    assert "dead-letter-spike" in kinds
    assert "consumer-lag" in kinds
    assert r["pipeline_health"]["dlq_depth"] == 7
    # below-threshold lag does not flag
    r2 = lr.compute_report(engine, "org-a", START, END,
                           health={"consumer_lag": 10, "dlq_depth": 0, "capture_drops": {}})
    assert not any(f["kind"] in ("consumer-lag", "dead-letter-spike") for f in r2["flags"])


def test_org_isolation(engine):
    _add_session(engine, 1, org="org-a")
    _add_session(engine, 2, org="org-b")
    _add_finding(engine, "s-org-b-2", when=START + timedelta(hours=1))
    ra = lr.compute_report(engine, "org-a", START, END, health=None)
    rb = lr.compute_report(engine, "org-b", START, END, health=None)
    rall = lr.compute_report(engine, None, START, END, health=None)
    assert ra["sessions"]["total"] == 1 and rb["sessions"]["total"] == 1
    assert rall["sessions"]["total"] == 2
    assert "weak-cipher-suite" not in ra["findings"]["by_rule"]   # finding belongs to org-b
    assert rb["findings"]["by_rule"] == {"weak-cipher-suite": 1}


def test_new_flows_and_fingerprints_only_first_seen_in_window(engine):
    # flow+fp existed BEFORE the window -> not new; one fresh pair -> new=1
    _add_session(engine, 0, flow="10.9.9.9:1->10.0.0.9:587", fp="fp-old",
                 when=START - timedelta(days=2))
    _add_session(engine, 1, flow="10.9.9.9:1->10.0.0.9:587", fp="fp-old",
                 when=START + timedelta(hours=1))
    _add_session(engine, 2, flow="10.8.8.8:2->10.0.0.9:587", fp="fp-new",
                 when=START + timedelta(hours=2))
    r = lr.compute_report(engine, "org-a", START, END, health=None)
    assert r["new_flows"] == 1
    assert r["new_fingerprints"] == 1


def test_suppression_and_delivery_counts(engine):
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO suppressions (org_id, rule_id, reason, created_by, "
            "status, created_at, expires_at, scope) VALUES "
            "('org-a', 'weak-cipher-suite', 'legacy host', 'a@x', 'approved', :t1, :exp1, '{}'), "
            "('org-a', 'old-rule', 'stale', 'a@x', 'approved', :t0, :exp0, '{}'), "
            "('org-b', 'weak-cipher-suite', 'other org', 'b@x', 'approved', :t1, :exp1, '{}')"),
            {"t1": START + timedelta(hours=1), "exp1": END + timedelta(days=30),
             "t0": START - timedelta(days=5), "exp0": START - timedelta(days=1)})
        c.execute(text(
            "INSERT INTO alert_deliveries (alert_id, channel, status, attempts, org_id, ts) "
            "VALUES ('al1', 'webhook', 'failed', 1, 'org-a', :t), "
            "('al2', 'webhook', 'sent', 1, 'org-a', :t)"), {"t": START + timedelta(hours=2)})
    r = lr.compute_report(engine, "org-a", START, END, health=None)
    assert r["suppressions"]["created_in_window"] == 1     # org-b + pre-window excluded
    assert r["suppressions"]["active_at_end"] == 1         # expired one excluded
    assert r["alert_delivery_failures"] == 1


def test_markdown_and_json_render_offline(engine, tmp_path):
    _add_session(engine, 0)
    r = lr.compute_report(engine, "org-a", START, END,
                          health={"consumer_lag": 0, "dlq_depth": 0, "capture_drops": {}})
    md = lr.to_markdown(r)
    assert "CipherPost live report" in md
    assert "no data left this host" in md
    # no full addresses in default output (privacy)
    assert "10.0.0." not in md and "10.0.0." not in str(r)
    (tmp_path / "r.json").write_text(str(r))


def test_cli_writes_files_and_exit_codes(engine, tmp_path, monkeypatch):
    _add_session(engine, 0)
    db_url = "sqlite:///" + str(tmp_path / "live.db")
    Base.metadata.create_all(create_engine(db_url))
    with engine.begin() as c:  # copy rows
        pass
    # move data: recreate in file db
    feng = create_engine(db_url)
    Base.metadata.create_all(feng)
    _add_session(feng, 0)
    feng.dispose()

    out = tmp_path / "rep"
    rc = lr.main(["--db-url", db_url, "--start", "2026-10-24", "--end", "2026-10-25",
                  "--org-id", "org-a", "--out", str(out), "--no-pipeline"])
    # one session at 03:00 -> coverage-gap flag -> exit 1 (flags are actionable)
    assert rc == 1
    assert (tmp_path / "rep.json").exists() and (tmp_path / "rep.md").exists()
    import json as _json
    saved = _json.loads((tmp_path / "rep.json").read_text())
    assert any(f["kind"] == "coverage-gap" for f in saved["flags"])
    assert "org-a" in (tmp_path / "rep.md").read_text()
    # bad window -> usage error
    rc2 = lr.main(["--db-url", db_url, "--start", "2026-10-25", "--end", "2026-10-24",
                   "--no-pipeline"])
    assert rc2 == 2
