"""Phase 4 Task 4: retraining gate, rollback, org isolation, thresholds."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _sa(five_tuple, rule_ids=(), tls_version=0x0303):
    from app.parsing.rules import SessionAnalysis
    from app.parsing.rules import Finding as RuleFinding
    sa = SessionAnalysis(session_id=five_tuple, protocol="SMTP",
                         five_tuple=five_tuple, is_starttls=False)
    sa.tls_version = tls_version
    sa.findings = [RuleFinding(rule_id=r, rule_name=r, severity="high",
                               title=r, description=r, reference="")
                   for r in rule_ids]
    return sa


def _entries(n_pos=60, n_neg=60):
    out = []
    for i in range(n_pos):
        out.append({"session_id": f"p{i}", "y": 1, "source": "analyst",
                    "five_tuple": f"10.0.0.{i % 20}:1-9.9.9.9:25",
                    "created_at": i, "sa": _sa(f"s{i}", ("expired-certificate",))})
    for i in range(n_neg):
        out.append({"session_id": f"n{i}", "y": 0, "source": "analyst",
                    "five_tuple": f"10.1.0.{i % 20}:1-9.9.9.9:25",
                    "created_at": 1000 + i, "sa": _sa(f"t{i}", ())})
    return out


def test_below_threshold_is_ranking_only(monkeypatch):
    from app.ml import retraining as _rt
    from app.core import config as cfg
    monkeypatch.setattr(cfg.settings, "MIN_ANALYST_LABELS_PER_CLASS", 50)
    ok, reason = _rt.check_threshold(_entries(3, 60))
    assert ok is False and "ranking-only" in reason
    ok, _ = _rt.check_threshold(_entries(50, 50))
    assert ok is True


def test_promotion_gate_accepts_lift_rejects_regression():
    from app.ml import retraining as _rt
    cur = {"f1": 0.70, "fp_rate": 0.10}
    ok, reason = _rt.promotion_gate("o", {"metrics": {"f1": 0.75, "fp_rate": 0.08}}, cur)
    assert ok is True and "promoted" in reason
    ok, reason = _rt.promotion_gate("o", {"metrics": {"f1": 0.71, "fp_rate": 0.08}}, cur)
    assert ok is False and "margin" in reason
    ok, reason = _rt.promotion_gate("o", {"metrics": {"f1": 0.80, "fp_rate": 0.15}}, cur)
    assert ok is False and "false-positive" in reason
    ok, _ = _rt.promotion_gate("o", {"metrics": {"f1": 0.5}}, None)
    assert ok is True  # first model has nothing to beat


def test_train_candidate_end_to_end_and_rollback(tmp_path, monkeypatch):
    from app.core import config as cfg
    monkeypatch.setattr(cfg.settings, "MODELS_DIR", str(tmp_path / "models"))
    monkeypatch.setattr(cfg.settings, "MIN_ANALYST_LABELS_PER_CLASS", 5)
    from app.ml import retraining as _rt
    from app.ml import registry as _reg

    class FakeDB:
        pass  # build path uses sqlite below instead

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E
    from datetime import datetime, timezone
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)()
    S.add(E.Organization(id="o", name="o"))
    now = datetime.now(timezone.utc)
    S.add(E.AnalysisJob(id="j", filename="x", pcap_path="x",
                        status=E.JobStatus.COMPLETED, org_id="o", created_at=now))
    for i in range(8):
        S.add(E.Session(id=f"s{i}", job_id="j", protocol="SMTP",
                        five_tuple=f"10.0.0.{i}:1-9.9.9.9:25",
                        src_ip="a", dst_ip="b", src_port=1, dst_port=25,
                        org_id="o", created_at=now))
        S.add(E.Finding(session_id=f"s{i}", rule_id="expired-certificate",
                        rule_name="w", severity=E.Severity.HIGH, title="t",
                        description="d", reference="", created_at=now))
        S.add(E.FindingFeedback(org_id="o", finding_id=i + 1,
                                rule_id="expired-certificate", session_id=f"s{i}",
                                verdict="confirmed" if i < 4 else "false_positive",
                                comment="", created_by="t", created_at=now))
    S.commit()
    out = _rt.train_candidate("o", S)
    assert out["status"] in ("candidate", "rejected"), out
    if out["status"] == "candidate":
        assert out["metrics"]["n"] == 8
        ok, _ = _rt.promotion_gate("o", out, None)
        assert ok is True
        promoted = _reg.promote_candidate("o", out["version"], "test")
        assert promoted and promoted["status"] == "active"
        back = _reg.rollback_org("o")
        assert back is not None  # superseded prior reactivates
    S.close()


def test_training_data_never_crosses_orgs():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models.entities as E
    from app.ml import retraining as _rt
    from datetime import datetime, timezone
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)()
    now = datetime.now(timezone.utc)
    for org in ("oa", "ob"):
        S.add(E.Organization(id=org, name=org))
        S.add(E.AnalysisJob(id="j" + org, filename="x", pcap_path="x",
                             status=E.JobStatus.COMPLETED, org_id=org, created_at=now))
        S.add(E.Session(id="s" + org, job_id="j" + org, protocol="SMTP",
                        five_tuple="a-b", src_ip="a", dst_ip="b",
                        src_port=1, dst_port=2, org_id=org, created_at=now))
        S.add(E.Finding(session_id="s" + org, rule_id="r", rule_name="w",
                        severity=E.Severity.HIGH, title="t", description="d",
                        reference="", created_at=now))
        S.add(E.FindingFeedback(org_id=org, finding_id=1, rule_id="r",
                                session_id="s" + org, verdict="confirmed",
                                comment="", created_by="t", created_at=now))
    S.commit()
    rows_a = _rt.build_analyst_dataset("oa", S)
    assert rows_a and all(r["session_id"] == "soa" for r in rows_a)
    rows_b = _rt.build_analyst_dataset("ob", S)
    assert all(r["session_id"] == "sob" for r in rows_b)
    S.close()


def test_org_scorers_are_isolated_instances():
    from app.live import analyze as _am

    class W(_am.AnalysisWorker):
        def __init__(self):
            self._org_scorers = {}
            self._org_model_versions = {}

    w = W()
    a = w._scorer_for("org-a")
    b = w._scorer_for("org-b")
    assert a is not b  # separate baselines; no shared training state
    assert w._scorer_for("org-a") is a  # cached, not rebuilt
