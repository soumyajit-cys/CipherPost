"""
Stage 4 eval: ML risk scoring with GROUPED, TIME-AWARE splits (Phase 4).

Usage:
  python -m app.ml.eval_ml <fixtures_dir> [--compare]

Default: grouped split (whole server groups, newest to test) + precision /
recall / F1 / AUC on held-out data. --compare additionally runs the legacy
random row-wise split so docs/ml-evaluation.md can show both side by side.
Labels here are rules-derived (source=rules); analyst-labeled evaluation
lives in app.ml.retraining (source=analyst).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.parsing.analysis import analyze_pcap  # noqa: E402
from app.parsing.rules import max_severity  # noqa: E402
from app.ml.ml_engine import SessionScorer  # noqa: E402
from app.ml.splits import grouped_time_split, server_of, leakage_report  # noqa: E402


def _label(sa) -> int:
    return 1 if max_severity(sa.findings) in ("medium", "high", "critical") else 0


def _metrics(y_true: list[int], y_score: list[float], threshold: float = 50.0) -> dict:
    from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
    y_pred = [1 if s >= threshold else 0 for s in y_score]
    out = {
        "n": len(y_true), "positives": int(sum(y_true)),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "auc": None,
    }
    try:
        if len(set(y_true)) == 2:
            out["auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
    except Exception:
        pass
    return out


def _score_all(scorer, items) -> tuple[list[int], list[float]]:
    yt, ys = [], []
    for _ent, sa in items:
        yt.append(_label(sa))
        try:
            ys.append(float(scorer.score(sa).risk.posture_score))
        except Exception:
            ys.append(0.0)
    return yt, ys


def main() -> dict:
    fixtures = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"
    compare = "--compare" in sys.argv
    trust = os.path.join(fixtures, "trusted_root.pem")
    with open(os.path.join(fixtures, "corpus_index.json")) as f:
        corpus = json.load(f)["files"]

    analyses = []
    for i, ent in enumerate(corpus):
        ap = analyze_pcap(os.path.join(fixtures, f"{ent['name']}.pcap"), trust_store=trust)
        if ap:
            analyses.append({"name": ent["name"], "sa": ap[0], "order": i,
                             "server": server_of(ap[0].five_tuple)})
    print(f"Loaded {len(analyses)} sessions")

    results = {}
    # Grouped, time-aware split (whole servers, newest first to test).
    train_g = [a["sa"] for a in analyses]
    scorer = SessionScorer(trust_store=trust)
    g_train_items = [(a["name"], a["sa"]) for a in analyses]
    tr, te = grouped_time_split(
        g_train_items,
        lambda it: server_of(it[1].five_tuple),
        lambda it: next((x["order"] for x in analyses if x["sa"] is it[1]), 0))
    leak = leakage_report(tr, te, lambda it: server_of(it[1].five_tuple))
    print(f"grouped split: train={len(tr)} test={len(te)} leaked={leak['leaked_groups']}")
    scorer.train([sa for _, sa in tr])
    yt, ys = _score_all(scorer, te)
    results["grouped"] = {"split": {"train": len(tr), "test": len(te),
                                    "leaked_groups": leak["leaked_groups"]},
                          "metrics": _metrics(yt, ys)}
    print("grouped held-out:", json.dumps(results["grouped"]["metrics"]))

    if compare:
        # Legacy random row-wise split for the honest side-by-side.
        from sklearn.model_selection import train_test_split
        idx = list(range(len(analyses)))
        tr_i, te_i = train_test_split(idx, test_size=0.2, random_state=42)
        scorer2 = SessionScorer(trust_store=trust)
        scorer2.train([analyses[i]["sa"] for i in tr_i])
        yt2, ys2 = _score_all(scorer2, [(analyses[i]["name"], analyses[i]["sa"]) for i in te_i])
        leak2 = leakage_report([analyses[i] for i in tr_i], [analyses[i] for i in te_i],
                               lambda a: a["server"])
        results["random_rowwise"] = {"split": {"train": len(tr_i), "test": len(te_i),
                                               "leaked_groups": leak2["leaked_groups"]},
                                     "metrics": _metrics(yt2, ys2)}
        print("random held-out: ", json.dumps(results["random_rowwise"]["metrics"]))
        print("leaked server groups under random split:", leak2["leaked_groups"])

    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
