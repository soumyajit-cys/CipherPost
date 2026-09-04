"""
Stage 4 eval: ML risk scoring performance + explicit rule-vs-ML disagreement report.

Usage: python -m app.ml.eval_ml <fixtures_dir>
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.parsing.analysis import analyze_pcap  # noqa: E402
from app.parsing.rules import max_severity  # noqa: E402
from app.ml.features import session_features_matrix, extract_features  # noqa: E402
from app.ml.ml_engine import SessionScorer  # noqa: E402


def main():
    fixtures = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"
    trust = os.path.join(fixtures, "trusted_root.pem")
    with open(os.path.join(fixtures, "corpus_index.json")) as f:
        corpus = json.load(f)["files"]

    analyses = []
    for ent in corpus:
        ap = analyze_pcap(os.path.join(fixtures, f"{ent['name']}.pcap"), trust_store=trust)
        if ap:
            analyses.append((ent, ap[0]))

    print(f"Loaded {len(analyses)} sessions")

    # Split: 80% train, 20% test
    split_idx = max(1, int(len(analyses) * 0.8))
    train = [a[1] for a in analyses[:split_idx]]
    test = analyses[split_idx:]

    scorer = SessionScorer(trust_store=trust)
    scorer.train(train)

    print(f"\nEvaluating {len(test)} held-out sessions...\n")
    print(f"{'name':30s} {'rules_risk':10s} {'ml_score':8s} {'ml_class':10s} "
          f"{'anomaly':8s} {'agreement':30s}")
    print("-" * 110)

    disagreements = []
    all_scores = []
    for ent, sa in test:
        result = scorer.score(sa)
        rule_risk = max_severity(sa.findings) in ("medium", "high", "critical")
        all_scores.append({
            "name": ent["name"],
            "rules_risk": rule_risk,
            "ml_score": result.risk.posture_score,
            "ml_class": result.risk.class_label,
            "anomaly": result.anomaly.is_anomaly,
            "agreement": result.rule_ml_agreement,
            "top_shap": [c.feature for c in result.shap_contributions[:3]],
        })
        print(f"{ent['name']:30s} {str(rule_risk):10s} {result.risk.posture_score:>8d} "
              f"{result.risk.class_label:10s} {str(result.anomaly.is_anomaly):8s} "
              f"{result.rule_ml_agreement:30s}")
        if result.rule_ml_agreement != "agrees":
            disagreements.append({
                "name": ent["name"],
                "agreement": result.rule_ml_agreement,
                "rule_risk": rule_risk,
                "ml_score": result.risk.posture_score,
                "top_shap": [c.feature for c in result.shap_contributions[:5]],
            })

    # Anomaly summary
    anomaly_count = sum(1 for s in all_scores if s["anomaly"])
    print(f"\nAnomaly count: {anomaly_count}/{len(all_scores)}")

    if disagreements:
        print(f"\n{'='*60}")
        print(f"RULES vs ML DISAGREEMENTS ({len(disagreements)}):")
        print(f"{'='*60}")
        for d in disagreements:
            print(f"  {d['name']}: {d['agreement']}")
            print(f"    rule_risk={d['rule_risk']}, ml_score={d['ml_score']}")
            print(f"    top SHAP features: {d['top_shap']}")
    else:
        print("\nNo disagreements between rules engine and ML model on held-out set.")

    # Full fleet scores
    print(f"\n{'='*60}")
    print("FULL FLEET POSTURE SCORES:")
    print(f"{'='*60}")
    for ent, sa in analyses:
        result = scorer.score(sa)
        print(f"  {ent['name']:30s} posture={result.risk.posture_score:>3d}/100  "
              f"anomaly={result.anomaly.is_anomaly}")


if __name__ == "__main__":
    main()