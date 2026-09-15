"""
Track 5: model registry, drift detection, disagreement report math.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))


def test_registry_roundtrip(tmp_path, monkeypatch):
    import app.ml.registry as reg
    monkeypatch.setattr(reg.settings, "MODELS_DIR", tmp_path)
    v1 = reg.record_training(50, ["a", "b"], params={"m": 1})
    assert v1.startswith("0.1.0-50-")
    assert reg.current_version() == v1
    v2 = reg.record_training(60, ["a", "b"])
    assert v2 != v1 and reg.current_version() == v2
    assert len(reg.history()) == 2


def test_scorer_stamps_version():
    from app.ml.ml_engine import SessionScorer
    from app.parsing.rules import SessionAnalysis
    sc = SessionScorer()
    sa = SessionAnalysis(session_id="x", protocol="SMTP",
                         five_tuple="a:1->b:25", is_starttls=False)
    out = sc.score(sa)  # untrained fallback path
    assert out.risk.model_version  # non-empty even without training


def test_drift_detects_shift_and_ignores_noise():
    import numpy as np
    from app.live.baseline import compute_drift
    rng = np.random.default_rng(0)
    ref = rng.normal(0, 1, size=(200, 6))
    same = rng.normal(0, 1, size=(100, 6))
    out = compute_drift(ref, same, [f"f{i}" for i in range(6)])
    assert out["verdict"] == "ok"
    shifted = rng.normal(0, 1, size=(100, 6)) + 5.0  # every feature moves
    out2 = compute_drift(ref, shifted, [f"f{i}" for i in range(6)])
    assert out2["verdict"] == "drift"
    assert len(out2["drifted"]) == 6
    # single-feature move is ok (policy rollout, not fleet drift)
    one = rng.normal(0, 1, size=(100, 6))
    one[:, 0] += 5.0
    out3 = compute_drift(ref, one, [f"f{i}" for i in range(6)])
    assert out3["verdict"] == "ok" and out3["drifted"] == ["f0"]
    # too little data
    assert compute_drift(ref[:2], same[:2], ["f0"])["verdict"] == "insufficient-data"


def test_disagreement_report_math():
    import sys
    sys.path.insert(0, os.path.abspath("scripts"))
    from ml_disagreement_report import build_report

    class FakeConn:
        def execute(self, *a, **k):
            class R:
                def all(self):
                    return [("s1", 90, "critical", "0.1.0-10-abc"),
                            ("s2", 10, "none", "0.1.0-10-abc"),
                            ("s3", 80, "none", "0.1.0-10-abc"),   # ml-more-severe
                            ("s4", 20, "high", "0.1.0-10-abc")]   # rules-more-severe
            return R()

    class FakeEngine:
        def connect(self):
            return self

        def __enter__(self):
            return FakeConn()

        def __exit__(self, *a):
            return False

    import sqlalchemy
    orig = sqlalchemy.create_engine
    sqlalchemy.create_engine = lambda *a, **k: FakeEngine()
    try:
        rep = build_report("sqlite://")
    finally:
        sqlalchemy.create_engine = orig
    assert rep["total_scored_sessions"] == 4
    assert rep["agreement"] == {"agrees": 2, "disagrees-ml-more-severe": 1,
                                "disagrees-rules-more-severe": 1}
    assert rep["agreement_rate"] == 0.5
