"""Export a redacted, self-contained issue bundle for a finding or session.

Reuses the diagnostics-bundle redaction code (app.api.main._redacted_config /
_mask_addresses): secrets are replaced with set/unset and IP addresses are
masked by default. An optional raw-frame slice is attached ONLY behind the
explicit --include-pcap flag, and only while raw segments are still inside
the rolling window (older refs resolve to 'purged').

Offline: reads the local database only; never sends data anywhere.

Usage:
  python scripts/export_issue_bundle.py --finding 123
  python scripts/export_issue_bundle.py --session <id> [--include-pcap] [--out bundle.json]

Exit codes: 0 ok, 1 not found, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

SCHEMA_VERSION = 1


def _mask(value: str) -> str:
    """Reuse the diagnostics-bundle address mask (first two octets kept)."""
    from app.api.main import _mask_addresses
    return _mask_addresses(value)


def _mask_obj(obj):
    """Recursively apply the address mask to any strings in a JSON-able object."""
    if isinstance(obj, str):
        return _mask(obj)
    if isinstance(obj, dict):
        return {k: _mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_mask_obj(v) for v in obj]
    return obj


def _jsonish(value):
    """JSONB columns come back as str on SQLite; parse, pass through else."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _session_metadata(sess) -> dict:
    """Session fields safe for an issue: metadata only, addresses masked.

    Never included: mail content (there is none stored), credentials,
    unmasked addresses. Five-tuple is masked via _mask_addresses.
    """
    from app.agent.meta import redact_host  # noqa: F401  (documented path)
    return _mask_obj({
        "session_id": sess.id,
        "protocol": sess.protocol,
        "five_tuple_masked": sess.five_tuple,
        "src_port": sess.src_port, "dst_port": sess.dst_port,
        "is_starttls": sess.is_starttls,
        "tls_version": sess.tls_version,
        "negotiated_cipher": sess.negotiated_cipher,
        "ja3": sess.ja3, "ja4": sess.ja4, "ja3s": sess.ja3s, "ja4s": sess.ja4s,
        "risk_score": sess.risk_score,
        "max_severity": sess.max_severity,
        "org_id": sess.org_id,
        "created_at": sess.created_at.isoformat()
        if hasattr(sess.created_at, "isoformat") else sess.created_at,
        "details": sess.details if isinstance(sess.details, dict) else None,
    })


def _raw_slice(sess, raw_dir: str | None) -> dict:
    """Optional --include-pcap slice: reuses RollingRawStore.read_frames on
    the session's raw_refs and wraps the frames in a minimal pcap."""
    from app.core.config import settings
    refs = ((sess.details or {}).get("raw_refs") if isinstance(sess.details, dict) else None) or []
    if not refs:
        return {"included": False, "reason": "session has no raw_refs"}
    from app.live.retention import RollingRawStore
    store = RollingRawStore(raw_dir or settings.RAW_CAPTURE_DIR,
                            settings.RAW_RETENTION_SECONDS,
                            settings.RAW_SEGMENT_SECONDS)
    frames = store.read_frames([tuple(r) for r in refs])
    found = len(frames)
    expected = len(refs)
    if not frames:
        return {"included": False, "reason":
                f"all {expected} raw refs purged or unreadable (rolling window)"}
    try:
        from scapy.all import Ether, wrpcap  # type: ignore
        import tempfile
        packets = []
        for raw in frames:
            try:
                packets.append(Ether(raw))
            except Exception:
                continue
        if not packets:
            return {"included": False, "reason": "no frames decoded as Ethernet"}
        fh = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        fh.close()
        wrpcap(fh.name, packets)
        data = Path(fh.name).read_bytes()
        Path(fh.name).unlink()
        import base64
        return {"included": True, "format": "pcap (base64)",
                "frames_expected": expected, "frames_decoded": len(packets),
                "pcap_b64": base64.b64encode(data).decode()}
    except Exception as e:
        return {"included": False, "reason": f"pcap wrap failed: {str(e)[:200]}",
                "frames_expected": expected, "frames_found": found}


def build_bundle(db_engine, finding_id: int | None = None,
                 session_id: str | None = None,
                 include_pcap: bool = False, raw_dir: str | None = None) -> tuple[dict, str]:
    """Returns (bundle, error). error is '' on success, 'not-found'/'usage'."""
    from sqlalchemy import text as _sql
    from app.core.config import settings

    sess = None
    finding = None
    with db_engine.connect() as conn:
        if finding_id is not None:
            row = conn.execute(_sql(
                "SELECT f.id, f.session_id, f.rule_id, f.rule_name, f.severity, "
                "f.title, f.description, f.reference, f.evidence, f.created_at "
                "FROM findings f WHERE f.id = :fid"), {"fid": finding_id}).first()
            if row is None:
                return {}, "not-found"
            finding = {
                "finding_id": row.id, "session_id": row.session_id,
                "rule_id": row.rule_id, "rule_name": row.rule_name,
                "severity": str(row.severity).lower(),
                "title": row.title, "description": row.description,
                "reference": row.reference,
                "evidence": _mask_obj(_jsonish(row.evidence)),
                "created_at": row.created_at.isoformat()
                if hasattr(row.created_at, "isoformat") else row.created_at,
            }
            session_id = session_id or row.session_id
        if session_id:
            srow = conn.execute(_sql(
                "SELECT * FROM sessions WHERE id = :sid"), {"sid": session_id}).first()
            if srow is None:
                return {}, "not-found"
            from app.models.entities import Session
            # map the row onto the ORM entity fields the serializer needs
            sess = Session()
            for col in Session.__table__.columns:
                setattr(sess, col.name, getattr(srow, col.name, None))
            sess.details = _jsonish(sess.details)

    # Reuse the diagnostics bundle's redacted config (single source of truth).
    from app.api.main import _redacted_config

    bundle = {
        "schema_version": SCHEMA_VERSION,
        "bundle_kind": "issue",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": settings.APP_VERSION,
        "finding": finding,
        "session": _session_metadata(sess) if sess is not None else None,
        "config_redacted": _redacted_config(),
        "redaction": {"secrets": "set/unset only",
                      "addresses": "masked by default (see app.api.main._mask_addresses)",
                      "unmasked_addresses": False},
        "raw_slice": _raw_slice(sess, raw_dir) if (include_pcap and sess is not None)
                     else {"included": False,
                           "reason": "not requested (use --include-pcap)"
                                     if not include_pcap else "no session"},
        "note": "Generated locally; attach to a GitHub issue per "
                "docs/live-run/triage.md. Contains no message bodies or credentials.",
    }
    return bundle, ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export a redacted issue bundle")
    ap.add_argument("--finding", type=int, default=None, help="finding id")
    ap.add_argument("--session", default=None, help="session id")
    ap.add_argument("--include-pcap", action="store_true",
                    help="attach the session's raw-frame slice (explicit opt-in; "
                         "only refs still inside the rolling window are included)")
    ap.add_argument("--raw-dir", default=None, help="override raw capture directory")
    ap.add_argument("--db-url", default=None, help="sync database URL override")
    ap.add_argument("--out", default=None, help="write JSON here (default stdout)")
    ap.add_argument("--install", action="store_true",
                    help="install-problem mode: versions + redacted config only")
    args = ap.parse_args(argv)

    if not args.install and args.finding is None and args.session is None:
        ap.error("one of --finding / --session / --install is required")
        return 2

    from app.core.config import settings
    from sqlalchemy import create_engine
    if args.install:
        from app.api.main import _redacted_config
        bundle = {
            "schema_version": SCHEMA_VERSION, "bundle_kind": "install",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_version": settings.APP_VERSION,
            "config_redacted": _redacted_config(),
            "redaction": {"secrets": "set/unset only", "unmasked_addresses": False},
            "note": "Install-problem bundle (no DB contents).",
        }
        print(json.dumps(bundle, indent=2))
        return 0

    engine = create_engine(args.db_url or settings.DATABASE_URL_SYNC)
    bundle, err = build_bundle(engine, args.finding, args.session,
                               include_pcap=args.include_pcap,
                               raw_dir=args.raw_dir)
    if err == "not-found":
        print("error: finding/session not found in the local database", file=sys.stderr)
        return 1
    text = json.dumps(bundle, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
