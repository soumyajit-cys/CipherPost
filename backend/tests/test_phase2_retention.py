"""Phase 2 Task 4: batch purge + legal hold (sqlite, no Postgres needed)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone, timedelta


def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E  # noqa
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)(), E


def test_batch_purge_deletes_old_sessions_findings():
    S, E = _db()
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=100)
    S.add(E.Organization(id="o", name="default"))
    S.add(E.AnalysisJob(id="j", filename="a.pcap", pcap_path="x",
                        status=E.JobStatus.COMPLETED, org_id="o"))
    for i in range(5):
        S.add(E.Session(id=f"s{i}", job_id="j", protocol="SMTP",
                        five_tuple=f"a:{i}-b:25", src_ip="a", dst_ip="b",
                        src_port=i, dst_port=25, org_id="o", created_at=old))
        S.add(E.Finding(session_id=f"s{i}", rule_id="r", rule_name="r",
                        severity=E.Severity.HIGH, title="t", description="d",
                        reference="", created_at=old))
    S.add(E.Session(id="fresh", job_id="j", protocol="SMTP", five_tuple="a-b",
                    src_ip="a", dst_ip="b", src_port=1, dst_port=25,
                    org_id="o", created_at=now))
    S.commit()
    from app.live.retention import DBRetention
    counts = {"n": 0}
    ret = DBRetention(session_factory=lambda: S, batch_size=2,
                      metrics=type("M", (), {"inc": staticmethod(
                          lambda name, n=1: counts.__setitem__("n", counts["n"] + n))})())
    totals = ret.purge_all(now=now)
    assert totals["sessions"] == 5
    assert totals["findings"] == 5
    assert S.query(E.Session).count() == 1
    assert counts["n"] >= 10  # per-batch metric reports
    S.close()


def test_legal_hold_survives_retention():
    S, E = _db()
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=100)
    S.add(E.Organization(id="o", name="default"))
    S.add(E.AnalysisJob(id="jhold", filename="h.pcap", pcap_path="x",
                        status=E.JobStatus.COMPLETED, org_id="o", legal_hold=True))
    S.add(E.Session(id="held-sess", job_id="jhold", protocol="SMTP",
                    five_tuple="a-b", src_ip="a", dst_ip="b",
                    src_port=1, dst_port=25, org_id="o", created_at=old))
    S.add(E.AnalysisJob(id="j2", filename="b.pcap", pcap_path="y",
                        status=E.JobStatus.COMPLETED, org_id="o"))
    S.add(E.Finding(session_id="held-sess", rule_id="r", rule_name="r",
                    severity=E.Severity.HIGH, title="t", description="d",
                    reference="", created_at=old, legal_hold=True))
    S.add(E.Finding(session_id="held-sess", rule_id="r2", rule_name="r2",
                    severity=E.Severity.LOW, title="t", description="d",
                    reference="", created_at=old))
    S.commit()
    from app.live.retention import DBRetention
    ret = DBRetention(session_factory=lambda: S, batch_size=100)
    totals = ret.purge_all(now=now)
    # held session survives via job hold; held finding survives; unheld finding purged
    assert S.get(E.Session, "held-sess") is not None
    assert totals["sessions"] == 0
    remaining = {f.rule_id for f in S.query(E.Finding).all()}
    assert "r" in remaining and "r2" not in remaining
    S.close()
