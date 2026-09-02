"""
Stage 3 evaluation: rules-engine precision/recall against the labeled corpus.

For every corpus session we run the full pipeline and treat ground-truth
expected_findings (rule IDs) as the reference set. We compute per-rule
precision/recall over condition-level occurrences, plus a per-session
report. Disagreements are explicitly printed.

Usage: python -m app.parsing.eval_rules <fixtures_dir> [--trust <root.pem>]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.parsing.analysis import analyze_pcap  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fixtures", default="tests/fixtures")
    ap.add_argument("--trust", default=None)
    args = ap.parse_args()

    idx_path = os.path.join(args.fixtures, "corpus_index.json")
    with open(idx_path) as f:
        idx = json.load(f)

    trust = args.trust or os.path.join(args.fixtures, "trusted_root.pem")
    if not os.path.exists(trust):
        trust = None

    # per-rule stats
    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    sessions = 0
    mismatches = []

    for ent in idx["files"]:
        pcap = os.path.join(args.fixtures, f"{ent['name']}.pcap")
        analyses = analyze_pcap(pcap, trust_store=trust)
        if not analyses:
            print(f"[WARN] {ent['name']}: no sessions analyzed")
            continue
        a = analyses[0]
        got = {f.rule_id for f in a.findings}
        expected = set(ent["expected_findings"])
        sessions += 1
        for r in expected | got:
            if r in expected and r in got:
                rule_stats[r]["tp"] += 1
            elif r in expected:
                rule_stats[r]["fn"] += 1
            elif r in got:
                rule_stats[r]["fp"] += 1
        diff = (got - expected) | (expected - got)
        if diff:
            mismatches.append((ent["name"], sorted(expected), sorted(got), sorted(diff)))

    print(f"\nEvaluated {sessions} sessions across {len(rule_stats)} distinct rules\n")
    print(f"{'rule':<42} {'tp':>3} {'fp':>3} {'fn':>3} {'precision':>10} {'recall':>10}")
    print("-" * 90)
    agg = {"tp": 0, "fp": 0, "fn": 0}
    for r, s in sorted(rule_stats.items()):
        prec = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 0.0
        rec = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0.0
        for k in agg:
            agg[k] += s[k]
        print(f"{r:<42} {s['tp']:>3} {s['fp']:>3} {s['fn']:>3} {prec:>10.2f} {rec:>10.2f}")
    ap = agg["tp"] / (agg["tp"] + agg["fp"]) if (agg["tp"] + agg["fp"]) else 0.0
    ar = agg["tp"] / (agg["tp"] + agg["fn"]) if (agg["tp"] + agg["fn"]) else 0.0
    print("-" * 90)
    print(f"{'TOTAL':<42} {agg['tp']:>3} {agg['fp']:>3} {agg['fn']:>3} {ap:>10.2f} {ar:>10.2f}")

    if mismatches:
        print("\n--- Mismatches (explicit disagreements) ---")
        for name, exp, got, diff in mismatches:
            print(f"{name}: expected={exp}")
            print(f"          got     ={got}")
            print(f"          diff    ={diff}")


if __name__ == "__main__":
    main()