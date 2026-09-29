"""Real-data eval harness (foundation only, no fabricated data).

Runs the analyzer over tests/real/manifest.json and reports per-rule
precision/recall plus every miss / false positive.

Usage:
  PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json
  PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json --json

Manifest schema: see tests/real/README.md. Empty manifest exits 0 with
"no real captures yet" (honest baseline, not a failure).

Comparison is per (pcap, session, rule_id):
- expected present=true  + predicted => TP; expected true + missing => MISS
- expected present=false + predicted => FALSE POSITIVE (only when explicitly labelled false)
- rules with no labels for a session are ignored (not counted).

Exit codes: 0 always (informational, not a CI gate) unless --strict is passed
and misses/false-positives exist (for future use when corpus matures).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text())
    assert data.get("version") == 1, "unsupported manifest version"
    return data


def analyze_pcap_file(pcap: Path) -> list:
    from app.parsing.analysis import analyze_pcap
    return analyze_pcap(str(pcap))


def predicted_rule_ids(session_analysis) -> set[str]:
    return {f.rule_id for f in (getattr(session_analysis, "findings", None) or [])}


def eval_manifest(manifest_path: Path, base_dir: Path | None = None) -> dict:
    manifest = load_manifest(manifest_path)
    base = base_dir or manifest_path.parent
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    misses: list[dict] = []
    false_positives: list[dict] = []
    sessions_total = 0
    for entry in manifest.get("captures", []):
        pcap = base / entry["pcap"]
        if not pcap.exists():
            misses.append({"pcap": entry["pcap"], "error": "pcap file missing"})
            continue
        try:
            analyses = analyze_pcap_file(pcap)
        except Exception as e:
            misses.append({"pcap": entry["pcap"], "error": f"analyzer crashed: {e}"})
            continue
        sessions_total += len(analyses)
        # index sessions by str(idx) for label lookup
        by_idx = {str(i): a for i, a in enumerate(analyses)}
        for exp in entry.get("expected_findings", []):
            rule = exp["rule_id"]
            sess_key = str(exp.get("session", "0"))
            present = bool(exp.get("present", True))
            pred = by_idx.get(sess_key)
            pred_ids = predicted_rule_ids(pred) if pred is not None else set()
            hit = rule in pred_ids
            if present and hit:
                per_rule[rule]["tp"] += 1
            elif present and not hit:
                per_rule[rule]["fn"] += 1
                misses.append({"pcap": entry["pcap"], "session": sess_key,
                               "rule_id": rule, "type": "miss", "notes": exp.get("notes", "")})
            elif not present and hit:
                per_rule[rule]["fp"] += 1
                false_positives.append({"pcap": entry["pcap"], "session": sess_key,
                                        "rule_id": rule, "type": "false-positive",
                                        "notes": exp.get("notes", "")})
            elif not present and not hit:
                per_rule[rule]["tp"] += 0  # true negative (not counted in P/R)
    # per-rule P/R
    rows = []
    for rule, c in sorted(per_rule.items()):
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        rows.append({"rule_id": rule, "tp": tp, "fp": fp, "fn": fn,
                     "precision": prec, "recall": rec})
    return {"captures": len(manifest.get("captures", [])),
            "sessions_total": sessions_total,
            "per_rule": rows,
            "misses": misses,
            "false_positives": false_positives}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Real-data eval (informational, not a gate)")
    ap.add_argument("manifest", nargs="?", default="tests/real/manifest.json")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit 2 if any miss/false-positive (for future mature corpus)")
    args = ap.parse_args(argv)
    mp = Path(args.manifest)
    if not mp.exists():
        print(f"manifest not found: {mp}", file=sys.stderr)
        return 1
    report = eval_manifest(mp)
    if report["captures"] == 0:
        print("real eval: no real captures yet (empty manifest) — add PCAPs per tests/real/README.md")
        return 0
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"real eval: {report['captures']} captures, {report['sessions_total']} sessions")
        print(f"{'rule':40} {'tp':>4} {'fp':>4} {'fn':>4} {'prec':>6} {'rec':>6}")
        for r in report["per_rule"]:
            prec = f"{r['precision']:.2f}" if r["precision"] is not None else "  n/a"
            rec = f"{r['recall']:.2f}" if r["recall"] is not None else "  n/a"
            print(f"{r['rule_id']:40} {r['tp']:4} {r['fp']:4} {r['fn']:4} {prec:>6} {rec:>6}")
        for m in report["misses"]:
            print(f"MISS {m}")
        for f in report["false_positives"]:
            print(f"FALSE-POSITIVE {f}")
    if args.strict and (report["misses"] or report["false_positives"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
