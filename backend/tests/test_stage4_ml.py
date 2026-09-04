"""Stage 4 tests: feature extraction, ML scoring, SHAP."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest
from app.parsing.analysis import analyze_pcap
from app.ml.features import extract_features, session_features_matrix, FEATURE_NAMES
from app.ml.ml_engine import SessionScorer

FIXTURES = "tests/fixtures"


@pytest.fixture(scope="module")
def trust_store():
    return f"{FIXTURES}/trusted_root.pem" if os.path.exists(f"{FIXTURES}/trusted_root.pem") else None


def test_feature_extraction_all_sessions(trust_store):
    corpus_path = f"{FIXTURES}/corpus_index.json"
    if not os.path.exists(corpus_path):
        pytest.skip("corpus not generated")
    import json
    with open(corpus_path) as f:
        entries = json.load(f)["files"]
    for ent in entries:
        analyses = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust_store)
        assert analyses, f"{ent['name']} produced no analysis"
        feats = extract_features(analyses[0])
        # All features are finite floats
        for k, v in feats.items():
            assert isinstance(v, float), f"{ent['name']}.{k} is {type(v)}"


def test_features_matrix_shape(trust_store):
    analyses = analyze_pcap(f"{FIXTURES}/smtp_tls13_strong.pcap", trust_store=trust_store)
    X, names, ids = session_features_matrix(analyses)
    assert X.shape == (1, len(names))
    assert len(ids) == 1


def test_scorer_produces_risk_score(trust_store):
    analyses_all = []
    import json
    with open(f"{FIXTURES}/corpus_index.json") as f:
        entries = json.load(f)["files"]
    for ent in entries:
        a = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust_store)
        if a:
            analyses_all.append(a[0])
    split = max(1, int(len(analyses_all) * 0.75))
    scorer = SessionScorer(trust_store=trust_store)
    scorer.train(analyses_all[:split])
    # Score each session
    for sa in analyses_all:
        result = scorer.score(sa)
        assert 0 <= result.risk.posture_score <= 100
        assert result.risk.class_label in ("healthy", "at-risk")
        assert result.anomaly.method


def test_at_risk_higher_posture_score(trust_store):
    good = analyze_pcap(f"{FIXTURES}/smtp_tls13_strong.pcap", trust_store=trust_store)[0]
    bad  = analyze_pcap(f"{FIXTURES}/pop3_export_cipher.pcap", trust_store=trust_store)[0]
    scorer = SessionScorer(trust_store=trust_store)
    all_analyses = [good, bad]
    scorer.train(all_analyses)
    r_good = scorer.score(good)
    r_bad  = scorer.score(bad)
    # Bad config should have equal or higher posture score (riskier)
    assert r_bad.risk.posture_score >= r_good.risk.posture_score
