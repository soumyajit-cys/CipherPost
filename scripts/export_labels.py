"""Export analyst labels with provenance (Task 7), and gate tests/real/ hygiene.

Offline: reads the local database only; never sends data anywhere.

Modes:
  export (default)   -> ML-ready dataset: rows {"session_id", "y", "source"}
                        exactly as app.ml.retraining expects (y=1 confirmed,
                        y=0 false_positive, accepted_risk excluded), with
                        source="analyst" and source="rules" kept in SEPARATE
                        sections, never merged. Full provenance per label:
                        who, when, rule_id, rule_version (tool version),
                        session_id, verdict, triage_category.
  --check-manifest   -> validate tests/real/manifest.json entries: every
                        capture must carry non-empty source + license;
                        entries with data_class != "lab" (live-run/pilot)
                        must additionally carry authorization + permission
                        + pseudonymized fields. Live-run/pilot data is
                        NEVER mixable into the lab test set unless the
                        entry is explicitly flagged with all fields filled.

Usage:
  python scripts/export_labels.py --out labels.json
  python scripts/export_labels.py --check-manifest tests/real/manifest.json

Exit codes: 0 ok, 1 check failed, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

TRIAGE_RE = re.compile(r"^\[triage:([a-z-]+)\]\s*")
TRIAGE_CATEGORIES = ("bug", "noise", "expected-behavior", "documented-limitation")


def parse_triage(comment: str | None) -> str | None:
    m = TRIAGE_RE.match(comment or "")
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_labels(engine, org_id: str | None = None,
                  tool_version: str | None = None) -> dict:
    from sqlalchemy import text as _sql
    from app.core.config import settings

    tool_version = tool_version or settings.APP_VERSION
    org_where = " AND org_id = :org" if org_id else ""
    params = {"org": org_id} if org_id else {}

    with engine.connect() as conn:
        fb_rows = conn.execute(_sql(
            "SELECT id, finding_id, rule_id, session_id, verdict, comment, "
            "created_by, created_at FROM finding_feedback "
            "WHERE 1=1" + org_where + " ORDER BY id"), params).mappings().all()
        # rules-derived labels (the engine's own verdicts on stored sessions),
        # kept in a SEPARATE section from analyst labels
        rules_rows = conn.execute(_sql(
            "SELECT f.id, f.session_id, f.rule_id, f.severity, f.created_at, "
            "s.ja4 FROM findings f JOIN sessions s ON f.session_id = s.id "
            "WHERE 1=1" + org_where.replace("org_id", "s.org_id") +
            " ORDER BY f.id"), params).mappings().all()

    provenance = []
    rows = []
    for r in fb_rows:
        triage = parse_triage(r["comment"])
        comment_wo = TRIAGE_RE.sub("", r["comment"] or "")
        if r["verdict"] == "confirmed":
            y = 1
        elif r["verdict"] == "false_positive":
            y = 0
        else:
            y = None  # accepted_risk: not a correctness label (retraining rule)
        provenance.append({
            "label_id": r["id"],
            "finding_id": r["finding_id"],
            "session_id": r["session_id"],
            "rule_id": r["rule_id"],
            "rule_version": tool_version,
            "who": r["created_by"],
            "when": r["created_at"].isoformat()
            if hasattr(r["created_at"], "isoformat") else r["created_at"],
            "verdict": r["verdict"],
            "y": y,
            "triage_category": triage,
            "comment": comment_wo,
        })
        if y is not None:
            rows.append({"session_id": r["session_id"], "y": y,
                         "source": "analyst"})

    # rules-derived rows: the rules engine's own output is a label ONLY in
    # the synthetic-corpus sense; here they are exported for disagreement
    # analysis, never merged into the analyst rows above.
    rules_labels = [{
        "session_id": r["session_id"], "rule_id": r["rule_id"],
        "severity": str(r["severity"]).lower(),
        "rule_version": tool_version,
        "observed_at": r["created_at"].isoformat()
        if hasattr(r["created_at"], "isoformat") else r["created_at"],
        "source": "rules",
    } for r in rules_rows]

    return {
        "schema_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "org_id": org_id,
        "tool_version": tool_version,
        "dataset_format": "app.ml.retraining build_analyst_dataset rows",
        "analyst": {"rows": rows, "provenance": provenance},
        "rules": {"rows": rules_labels},   # separate section: never merged
        "note": ("accepted_risk labels are excluded from y (ambiguous); "
                 "source=analyst and source=rules are never mixed. "
                 "Live-run data must not enter tests/real/ without the "
                 "explicit flagged import (see --check-manifest)."),
    }


# ---------------------------------------------------------------------------
# tests/real/ manifest hygiene check
# ---------------------------------------------------------------------------

REQUIRED_BASE = ("pcap", "source", "license")
REQUIRED_NON_LAB = ("authorization", "permission")
DATA_CLASSES = ("lab", "live-run", "pilot")


def check_manifest(manifest: dict) -> tuple[list[str], list[str]]:
    """Returns (errors, warnings). lab = generated in this repo's lab;
    live-run/pilot entries need explicit authorization + permission +
    pseudonymized fields (and live-run data must be flagged as such)."""
    errors: list[str] = []
    warnings: list[str] = []
    for i, cap in enumerate(manifest.get("captures", [])):
        where = f"captures[{i}] ({cap.get('pcap', '?')})"
        for field in REQUIRED_BASE:
            if not str(cap.get(field, "")).strip():
                errors.append(f"{where}: missing required field '{field}'")
        data_class = cap.get("data_class")
        if data_class is None:
            warnings.append(
                f"{where}: no 'data_class' (lab|live-run|pilot) — treating as "
                f"lab; new entries MUST set it")
            continue
        if data_class not in DATA_CLASSES:
            errors.append(f"{where}: unknown data_class {data_class!r} "
                          f"(expected one of {DATA_CLASSES})")
            continue
        if data_class in ("live-run", "pilot"):
            for field in REQUIRED_NON_LAB:
                if not str(cap.get(field, "")).strip():
                    errors.append(f"{where}: data_class={data_class} requires "
                                  f"non-empty '{field}'")
            if not cap.get("pseudonymized"):
                errors.append(
                    f"{where}: data_class={data_class} requires "
                    f"'pseudonymized': true (real addresses must be hashed/"
                    f"truncated before commit; see app.agent.meta.redact_host)")
    return errors, warnings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Label export + manifest hygiene")
    ap.add_argument("--out", default=None, help="write export JSON here")
    ap.add_argument("--org-id", default=None)
    ap.add_argument("--check-manifest", default=None,
                    help="path to tests/real/manifest.json to check instead of exporting")
    args = ap.parse_args(argv)

    if args.check_manifest:
        path = Path(args.check_manifest)
        if not path.exists():
            print(f"error: {path} not found", file=sys.stderr)
            return 2
        errors, warnings = check_manifest(json.loads(path.read_text()))
        for w in warnings:
            print(f"WARN: {w}")
        for e in errors:
            print(f"FAIL: {e}")
        if errors:
            print(f"manifest check FAILED ({len(errors)} error(s))")
            return 1
        print(f"manifest check OK ({len(warnings)} warning(s))")
        return 0

    from app.core.config import settings as _s
    from sqlalchemy import create_engine
    engine = create_engine(_s.DATABASE_URL_SYNC)
    data = export_labels(engine, org_id=args.org_id)
    text = json.dumps(data, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out} ({len(data['analyst']['rows'])} analyst rows, "
              f"{len(data['rules']['rows'])} rules rows)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
