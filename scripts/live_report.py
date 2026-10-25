"""Live-run daily/period report (Task 3): offline Markdown + JSON summaries.

Reads ONLY the local database (plus optional local Redis for pipeline
health). Never sends data anywhere. Org-scoped when --org-id is given;
respects pseudonymization by never printing addresses (any future address
output goes through app.agent.meta.redact_host).

Usage:
  python scripts/live_report.py                       # last 24h, stdout
  python scripts/live_report.py --start 2026-10-24 --end 2026-10-25 \
      --out reports/live --org-id <org>               # writes .md + .json

Exit codes: 0 ok, 2 usage error.
Metric definitions: docs/live-run/report-reference.md (single source).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

DEFAULT_FLAG_PCT = 50.0  # % change vs previous period that gets flagged


def _parse_dt(s: str, end_of_day: bool = False) -> datetime:
    """ISO date or datetime -> aware UTC datetime. Date-only end is exclusive
    end-of-day (so --end 2026-10-25 covers through 23:59:59)."""
    if "T" in s or " " in s:
        dt = datetime.fromisoformat(s.replace(" ", "T"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    d = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    if end_of_day:
        d = d + timedelta(days=1) - timedelta(seconds=1)
    return d


# ---------------------------------------------------------------------------
# Core computation (engine-agnostic; tests pass a SQLite engine)
# ---------------------------------------------------------------------------

def compute_report(engine, org_id: str | None, start: datetime, end: datetime,
                   health: dict | None = None,
                   flag_pct: float = DEFAULT_FLAG_PCT) -> dict:
    """Build the report dict. `health` is an injected pipeline-health dict so
    tests can simulate dead-letter spikes / capture stops without Redis."""
    from sqlalchemy import text as _sql

    prev_end = start
    prev_start = start - (end - start)
    params = {"start": start, "end": end,
              "pstart": prev_start, "pend": prev_end}
    # leading space so ":end" + org_where never fuses into ":endAND"
    org_where = " AND s.org_id = :org" if org_id else ""
    org_params = {"org": org_id} if org_id else {}

    def q(sql: str, extra: dict | None = None) -> list:
        import re as _re
        all_params = {**params, **org_params, **(extra or {})}
        # bind only parameters the statement actually references (SQLAlchemy
        # raises on bound names absent from the text() construct)
        used = set(_re.findall(r"(?<![:\w]):(\w+)", sql))
        stmt = _sql(sql).bindparams(**{k: v for k, v in all_params.items()
                                       if k in used})
        with engine.connect() as conn:
            return conn.execute(stmt).all()

    # --- sessions ----------------------------------------------------------
    total, total_prev = q(
        "SELECT COUNT(*), "
        "  (SELECT COUNT(*) FROM sessions sp WHERE sp.created_at >= :pstart "
        "   AND sp.created_at < :pend " + org_where.replace("s.", "sp.") + ") "
        "FROM sessions s WHERE s.created_at >= :start AND s.created_at < :end" + org_where
    )[0]
    # Date/time bucketing is done on CAST(... AS TEXT): Postgres renders
    # 'YYYY-MM-DD HH:MM:SS+00', SQLite 'YYYY-MM-DD HH:MM:SS.ffffff' — the
    # first 10 chars are the day, first 13 the hour in both.
    per_day = q(
        "SELECT substr(CAST(s.created_at AS TEXT), 1, 10), COUNT(*) FROM sessions s "
        "WHERE s.created_at >= :start AND s.created_at < :end" + org_where +
        " GROUP BY 1 ORDER BY 1")
    per_protocol = q(
        "SELECT s.protocol, COUNT(*) FROM sessions s "
        "WHERE s.created_at >= :start AND s.created_at < :end" + org_where +
        " GROUP BY 1 ORDER BY 2 DESC")
    enc, plain = q(
        "SELECT SUM(CASE WHEN s.tls_version IS NOT NULL THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN s.tls_version IS NULL THEN 1 ELSE 0 END) FROM sessions s "
        "WHERE s.created_at >= :start AND s.created_at < :end" + org_where
    )[0]
    versions = q(
        "SELECT COALESCE(s.tls_version, 'none'), COUNT(*) FROM sessions s "
        "WHERE s.created_at >= :start AND s.created_at < :end" + org_where +
        " GROUP BY 1 ORDER BY 2 DESC")
    ciphers = q(
        "SELECT COALESCE(s.negotiated_cipher, 'none'), COUNT(*) FROM sessions s "
        "WHERE s.created_at >= :start AND s.created_at < :end" + org_where +
        " GROUP BY 1 ORDER BY 2 DESC")
    # --- new flows / fingerprints (first-ever appearance inside the window) --
    # NOTE: the GROUP BY is NOT window-restricted; HAVING checks the MIN.
    new_flows = q(
        "SELECT COUNT(*) FROM (SELECT s.five_tuple FROM sessions s "
        "WHERE 1=1 " + org_where + " GROUP BY s.five_tuple "
        "HAVING MIN(s.created_at) >= :start AND MIN(s.created_at) < :end) t")[0][0]
    new_fps = q(
        "SELECT COUNT(*) FROM (SELECT s.ja4 FROM sessions s "
        "WHERE s.ja4 IS NOT NULL" + org_where + " GROUP BY s.ja4 "
        "HAVING MIN(s.created_at) >= :start AND MIN(s.created_at) < :end) t")[0][0]
    # --- findings -----------------------------------------------------------
    by_rule = q(
        "SELECT f.rule_id, COUNT(*) FROM findings f JOIN sessions s "
        "ON f.session_id = s.id WHERE f.created_at >= :start "
        "AND f.created_at < :end" + org_where + " GROUP BY 1 ORDER BY 2 DESC")
    by_sev = q(
        "SELECT CAST(f.severity AS TEXT), COUNT(*) FROM findings f "
        "JOIN sessions s ON f.session_id = s.id WHERE f.created_at >= :start "
        "AND f.created_at < :end" + org_where + " GROUP BY 1")
    # severity is stored as the enum member name (e.g. 'HIGH'); report lowercase
    by_sev = {str(s).lower(): int(n) for s, n in by_sev}
    # --- feedback + suppressions -------------------------------------------
    feedback = q(
        "SELECT verdict, COUNT(*) FROM finding_feedback "
        "WHERE created_at >= :start AND created_at < :end" +
        (" AND org_id = :org" if org_id else "") + " GROUP BY 1")
    sup_new, sup_active = q(
        "SELECT SUM(CASE WHEN created_at >= :start AND created_at < :end "
        "THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN expires_at > :end THEN 1 ELSE 0 END) FROM suppressions" +
        (" WHERE org_id = :org" if org_id else ""))[0]
    # --- alert delivery failures in window ----------------------------------
    delivery_fail = q(
        "SELECT COUNT(*) FROM alert_deliveries WHERE status = 'failed' "
        "AND ts >= :start AND ts < :end" +
        (" AND org_id = :org" if org_id else ""))[0][0]
    # --- gaps: hours with zero sessions -------------------------------------
    gaps = []
    cur = start.replace(minute=0, second=0, microsecond=0)
    counts_by_hour = dict(q(
        "SELECT substr(CAST(s.created_at AS TEXT), 1, 13), COUNT(*) "
        "FROM sessions s WHERE s.created_at >= :start AND s.created_at < :end" +
        org_where + " GROUP BY 1"))
    while cur < end:
        key = cur.strftime("%Y-%m-%d %H")
        if int(counts_by_hour.get(key, 0)) == 0:
            gaps.append(key)
        cur += timedelta(hours=1)

    enc = int(enc or 0)
    plain = int(plain or 0)
    encrypted_share = round(enc / total, 4) if total else None

    # --- flags (stopped capture etc.) ---------------------------------------
    flags = []
    if total_prev == 0 and total > 0:
        pass  # first period with data: nothing to compare
    elif total_prev > 0 and total == 0:
        flags.append({"kind": "capture-stop-suspected",
                      "detail": f"0 sessions in [{start.isoformat()}, {end.isoformat()}) "
                                f"vs {total_prev} in the previous period"})
    elif total_prev > 0:
        change = (total - total_prev) / total_prev * 100.0
        if change <= -flag_pct:
            flags.append({"kind": "sessions-drop",
                          "detail": f"sessions {total} vs {total_prev} prev "
                                    f"({change:.1f}% <= -{flag_pct}%)."})
    if gaps:
        flags.append({"kind": "coverage-gap",
                      "detail": f"{len(gaps)} hour(s) with zero sessions: "
                                f"{gaps[:5]}{'...' if len(gaps) > 5 else ''}"})
    if health:
        dlq = health.get("dlq_depth", 0)
        if dlq:
            flags.append({"kind": "dead-letter-spike",
                          "detail": f"dead-letter depth {dlq} > 0"})
        lag = health.get("consumer_lag", 0)
        if lag > 1000:
            flags.append({"kind": "consumer-lag",
                          "detail": f"sessions stream lag {lag} > 1000"})
        if health.get("capture_drops"):
            flags.append({"kind": "capture-drops",
                          "detail": f"capture drop counters: {health['capture_drops']}"})
        if delivery_fail:
            flags.append({"kind": "alert-delivery-failures",
                          "detail": f"{delivery_fail} failed alert deliveries in window"})

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "previous_window": {"start": prev_start.isoformat(),
                            "end": prev_end.isoformat()},
        "org_id": org_id,
        "sessions": {
            "total": int(total), "total_previous": int(total_prev),
            "per_day": {str(d): int(n) for d, n in per_day},
            "per_protocol": {p: int(n) for p, n in per_protocol},
            "encrypted": int(enc), "plaintext": int(plain),
            "encrypted_share": encrypted_share,
            "tls_versions": {v: int(n) for v, n in versions},
            "ciphers": {c: int(n) for c, n in ciphers},
        },
        "new_flows": int(new_flows),
        "new_fingerprints": int(new_fps),
        "findings": {
            "by_rule": {r: int(n) for r, n in by_rule},
            "by_severity": dict(by_sev),
        },
        "feedback": {v: int(n) for v, n in feedback},
        "suppressions": {"created_in_window": int(sup_new or 0),
                         "active_at_end": int(sup_active or 0)},
        "pipeline_health": health or {"note": "not collected (offline mode)"},
        "alert_delivery_failures": int(delivery_fail),
        "gaps_zero_session_hours": gaps,
        "flags": flags,
        "metric_definitions": "docs/live-run/report-reference.md",
    }


# ---------------------------------------------------------------------------
# Pipeline health (local Redis, best-effort; reuses app.live.health helpers)
# ---------------------------------------------------------------------------

def collect_pipeline_health() -> dict:
    """Local-only snapshot: consumer lag, DLQ depth, capture drops.
    Never queries anything off-host."""
    out: dict = {"consumer_lag": 0, "dlq_depth": 0, "capture_drops": {}}
    try:
        from app.core.config import settings as _s
        import redis as _redis
        from app.live.streams import dlq_name as _dlq
        r = _redis.Redis.from_url(_s.REDIS_URL, decode_responses=True,
                                  socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        out["consumer_lag"] = int(r.xlen(_s.SESSION_STREAM) or 0)
        out["dlq_depth"] = int(r.xlen(_dlq(_s.SESSION_STREAM)) or 0)
        drops: dict = {}
        for k in r.keys("cipherpost:metrics:*"):
            try:
                vals = json.loads(r.get(k) or "{}")
                for m, v in (vals or {}).items():
                    if "dropped" in m and isinstance(v, (int, float)):
                        drops[m] = drops.get(m, 0) + v
            except Exception:
                continue
        out["capture_drops"] = drops
    except Exception as e:
        out["error"] = str(e)[:200]
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def to_markdown(r: dict) -> str:
    s = r["sessions"]
    lines = [
        f"# CipherPost live report — {r['window']['start'][:10]}",
        "",
        f"Window: `{r['window']['start']}` → `{r['window']['end']}` "
        f"(previous: `{r['previous_window']['start']}` → "
        f"`{r['previous_window']['end']}`)",
        f"Org: `{r['org_id'] or 'all'}`",
        "",
    ]
    if r["flags"]:
        lines += ["## Flags", ""]
        for f in r["flags"]:
            lines.append(f"- **{f['kind']}**: {f['detail']}")
        lines.append("")
    lines += [
        "## Sessions",
        "",
        f"- total: **{s['total']}** (previous period: {s['total_previous']})",
        f"- encrypted: {s['encrypted']} ({s['encrypted_share'] if s['encrypted_share'] is not None else 'n/a'} share), "
        f"plaintext: {s['plaintext']}",
        "- per protocol: " + (", ".join(f"{p}={n}" for p, n in s["per_protocol"].items()) or "none"),
        "- per day: " + (", ".join(f"{d}={n}" for d, n in s["per_day"].items()) or "none"),
        f"- new flows: {r['new_flows']}; new client fingerprints (JA4): {r['new_fingerprints']}",
        "",
        "### TLS versions",
        "",
    ]
    lines += [f"- {v}: {n}" for v, n in s["tls_versions"].items()] or ["- none"]
    lines += ["", "### Ciphers (top 10)", ""]
    items = list(s["ciphers"].items())
    for c, n in items[:10]:
        lines.append(f"- {c}: {n}")
    if len(items) > 10:
        lines.append(f"- _other ({len(items) - 10} values)_: "
                     f"{sum(n for _, n in items[10:])}")
    lines += [
        "",
        "## Findings",
        "",
        "- by severity: " + (", ".join(f"{k}={v}" for k, v in r["findings"]["by_severity"].items()) or "none"),
    ]
    lines += [f"- {rule}: {n}" for rule, n in r["findings"]["by_rule"].items()]
    lines += [
        "",
        "## Feedback & suppressions",
        "",
        "- feedback verdicts: " + (", ".join(f"{k}={v}" for k, v in r["feedback"].items()) or "none"),
        f"- suppressions: {r['suppressions']['created_in_window']} created in window, "
        f"{r['suppressions']['active_at_end']} active at window end",
        f"- alert delivery failures: {r['alert_delivery_failures']}",
        "",
        "## Pipeline health",
        "",
    ]
    ph = r["pipeline_health"]
    if "error" in ph:
        lines.append(f"- **unavailable**: {ph['error']}")
    else:
        lines += [
            f"- consumer lag (sessions stream): {ph.get('consumer_lag', 'n/a')}",
            f"- dead-letter depth: {ph.get('dlq_depth', 'n/a')}",
            f"- capture drops: {ph.get('capture_drops') or 'none'}",
        ]
    lines += [
        "",
        "## Gaps (hours with zero sessions)",
        "",
    ]
    lines += [f"- {g}" for g in r["gaps_zero_session_hours"]] or ["- none"]
    lines += [
        "",
        "_Metric definitions: docs/live-run/report-reference.md. "
        "Generated locally by scripts/live_report.py; no data left this host._",
        ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline live-run report")
    ap.add_argument("--start", default=None, help="ISO date/datetime (UTC)")
    ap.add_argument("--end", default=None, help="ISO date/datetime (UTC); date-only means end-of-day")
    ap.add_argument("--org-id", default=None, help="restrict to one org")
    ap.add_argument("--out", default=None, help="output path prefix (writes .md and .json)")
    ap.add_argument("--format", default="both", choices=["md", "json", "both"])
    ap.add_argument("--db-url", default=None, help="sync database URL override")
    ap.add_argument("--no-pipeline", action="store_true",
                    help="skip the local Redis pipeline-health snapshot")
    ap.add_argument("--flag-pct", type=float, default=DEFAULT_FLAG_PCT,
                    help="%% change vs previous period that raises a flag (default 50)")
    args = ap.parse_args(argv)

    end = _parse_dt(args.end, end_of_day=True) if args.end else \
        datetime.now(timezone.utc).replace(microsecond=0)
    start = _parse_dt(args.start) if args.start else \
        end - timedelta(days=1) + timedelta(seconds=1)
    if start >= end:
        print("error: --start must be before --end", file=sys.stderr)
        return 2

    from app.core.config import settings as _s
    from sqlalchemy import create_engine
    engine = create_engine(args.db_url or _s.DATABASE_URL_SYNC)
    health = None if args.no_pipeline else collect_pipeline_health()
    report = compute_report(engine, args.org_id, start, end, health,
                            flag_pct=args.flag_pct)

    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        if args.format in ("json", "both"):
            outp.with_suffix(".json").write_text(json.dumps(report, indent=2))
        if args.format in ("md", "both"):
            outp.with_suffix(".md").write_text(to_markdown(report))
        print(f"wrote {outp.with_suffix('.json')} / {outp.with_suffix('.md')}"
              if args.format == "both" else f"wrote {outp.with_suffix('.' + args.format)}")
    else:
        if args.format in ("json", "both"):
            print(json.dumps(report, indent=2))
        if args.format in ("md", "both"):
            print(to_markdown(report))

    return 1 if report["flags"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
