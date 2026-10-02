"""Evidence bundles (Phase 4 Task 6).

Tamper-evident, hash-chained bundle of report records for audits.
Each record links to the previous hash; verify_bundle recomputes
the chain and checks manifest counts. Unobservable items are
labeled, never filled in.
"""
from __future__ import annotations

import hashlib
import json


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _record_hash(prev: str, seq: int, rtype: str, body: dict) -> str:
    h = hashlib.sha256()
    h.update(prev.encode())
    h.update(str(seq).encode())
    h.update(rtype.encode())
    h.update(_canonical(body).encode())
    return h.hexdigest()


def build_bundle(report: dict, suppressions: list | None = None,
                 retention: dict | None = None,
                 versions: dict | None = None) -> dict:
    """Build a hash-chained bundle from report + context."""
    report = report or {}
    suppressions = suppressions or []
    records: list[dict] = []
    prev = "GENESIS"
    seq = 0

    def _append(rtype: str, body: dict):
        nonlocal prev, seq
        rec_hash = _record_hash(prev, seq, rtype, body)
        records.append({"seq": seq, "type": rtype, "body": body,
                        "prev": prev, "hash": rec_hash})
        prev = rec_hash
        seq += 1

    _append("report.meta", {"filename": report.get("filename", ""),
                            "generated_at": report.get("generated_at", "")})
    for s in report.get("sessions", []) or []:
        _append("session", dict(s))
    for f in report.get("findings", []) or []:
        _append("finding", dict(f))
    for lim in report.get("limitations", []) or []:
        _append("limitation", {"note": lim, "observable": False})
    for s in suppressions:
        _append("suppression", dict(s) if isinstance(s, dict) else {"value": s})

    findings = report.get("findings", []) or []
    observed = sum(1 for f in findings if isinstance(f, dict) and f.get("observed", True))
    unobservable = (sum(1 for f in findings if isinstance(f, dict) and not f.get("observed", True))
                    + len(report.get("limitations", []) or []))

    manifest = {
        "record_count": len(records),
        "root_hash": prev,
        "labels": {"observed": observed, "unobservable": unobservable},
        "versions": versions or {},
        "retention": retention or {},
        "suppression_count": len(suppressions),
    }
    return {"manifest": manifest, "records": records}


def verify_bundle(bundle: dict) -> dict:
    """Recompute chain; return {ok, reason?, checked}."""
    try:
        manifest = bundle.get("manifest", {})
        records = bundle.get("records", [])
        if manifest.get("record_count") != len(records):
            return {"ok": False, "reason": "count mismatch", "checked": len(records)}
        prev = "GENESIS"
        for rec in records:
            expected = _record_hash(prev, rec["seq"], rec["type"], rec["body"])
            if expected != rec.get("hash") or rec.get("prev") != prev:
                return {"ok": False, "reason": f"tamper at seq {rec.get('seq')}",
                        "checked": rec.get("seq")}
            prev = rec["hash"]
        if manifest.get("root_hash") != prev:
            return {"ok": False, "reason": "root mismatch", "checked": len(records)}
        return {"ok": True, "checked": len(records)}
    except Exception as e:
        return {"ok": False, "reason": str(e)[:200], "checked": 0}
