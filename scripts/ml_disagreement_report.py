"""
Periodic rule-vs-ML disagreement report (track 5).

Trust artifact for stakeholders skeptical of the ML layer: compares the
deterministic rules verdict against the ML posture on every stored session.

Approximation (documented): per-session agreement labels are not stored
historically, so ML-at-risk is proxied by risk_score >= 50 and rules-at-risk
by max_severity in {medium, high, critical} — the same thresholds the live
scorer uses. Interpret small disagreement rates as healthy; a rising
disagrees-ml-more-severe rate after retraining warrants investigation.

Usage:
    PYTHONPATH=backend/. python scripts/ml_disagreement_report.py [--out reports/]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


def build_report(db_url: str | None = None) -> dict:
    from sqlalchemy import create_engine, text
    from app.core.config import settings
    engine = create_engine(db_url or settings.DATABASE_URL_SYNC)
    with engine.connect() as conn:
        try:
            rows = conn.execute(text(
                "SELECT id, risk_score, max_severity, model_version FROM sessions "
                "WHERE risk_score IS NOT NULL")).all()
        except Exception as e:
            return {"error": f"query failed: {e}", "total": 0}
    counts = Counter()
    versions = Counter()
    examples: dict[str, list] = {"disagrees-ml-more-severe": [],
                                 "disagrees-rules-more-severe": []}
    for sid, score, sev, ver in rows:
        rule_risk = (sev or "none") in ("medium", "high", "critical")
        ml_risk = (score or 0) >= 50
        if rule_risk == ml_risk:
            label = "agrees"
        elif ml_risk:
            label = "disagrees-ml-more-severe"
        else:
            label = "disagrees-rules-more-severe"
        counts[label] += 1
        versions[ver or "unknown"] += 1
        if label != "agrees" and len(examples[label]) < 10:
            examples[label].append({"session_id": sid, "risk_score": score,
                                    "max_severity": sev, "model_version": ver})
    total = sum(counts.values())
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_scored_sessions": total,
        "agreement": dict(counts),
        "agreement_rate": round(counts["agrees"] / total, 4) if total else None,
        "by_model_version": dict(versions),
        "examples": examples,
        "method_note": ("ML-at-risk proxied by risk_score>=50; rules-at-risk by "
                        "max_severity in {medium,high,critical} (live scorer thresholds)."),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Rule-vs-ML disagreement report")
    ap.add_argument("--out", default="data/reports",
                    help="directory for report JSON + markdown")
    ap.add_argument("--db-url", default=None)
    args = ap.parse_args(argv)
    report = build_report(args.db_url)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    (out / f"disagreement-{stamp}.json").write_text(json.dumps(report, indent=2))
    lines = ["# Rule-vs-ML disagreement report", "",
             f"Generated {report.get('generated_at')}",
             f"Scored sessions: {report.get('total_scored_sessions')}", "",
             "## Agreement", ""]
    for k, v in (report.get("agreement") or {}).items():
        lines.append(f"- {k}: {v}")
    lines += ["", f"Agreement rate: {report.get('agreement_rate')}",
              "", "## By model version", ""]
    for k, v in (report.get("by_model_version") or {}).items():
        lines.append(f"- {k}: {v}")
    lines += ["", f"_{report.get('method_note', '')}_", ""]
    (out / f"disagreement-{stamp}.md").write_text("\n".join(lines))
    print(f"wrote {out}/disagreement-{stamp}.{{json,md}} "
          f"({report.get('total_scored_sessions', 0)} sessions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
