"""`cipherpost` offline CLI (Phase 3 Task 4): no server, DB, or Redis required.

Engine imports are limited to `app.parsing` (+ `app.proactive` matchers):
importing this module must never pull fastapi/redis/sqlalchemy/celery.

Exit codes (documented in docs/cli.md):
  0 clean (no findings at/above --fail-on)
  1 findings at/above threshold
  2 usage/error
  3 parse failure (unreadable/corrupt PCAP)
"""
from __future__ import annotations

import argparse
import ast
import json
import sys

SCHEMA_VERSION = 1
EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, EXIT_PARSE = 0, 1, 2, 3
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def version() -> str:
    try:
        from pathlib import Path
        return (Path(__file__).resolve().parents[0] / "VERSION").read_text().strip()
    except Exception:
        return "0.0.0-unknown"


def rule_catalog() -> list[dict]:
    """Rule metadata parsed from the rule code itself (single source of truth).

    Reads each `sa.add(rule_id=..., ...)` call's string literals via AST, so
    `rules list|explain` can never drift from the engine.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[0] / "parsing" / "rules.py").read_text()
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add"):
            continue
        kw = {}
        for k in node.keywords:
            if isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                kw[k.arg] = k.value.value
        if "rule_id" in kw:
            out.append({"rule_id": kw.get("rule_id", ""),
                        "rule_name": kw.get("rule_name", ""),
                        "severity": kw.get("severity", ""),
                        "title": kw.get("title", ""),
                        "description": kw.get("description", ""),
                        "reference": kw.get("reference", "")})
    seen, unique = set(), []
    for r in out:
        if r["rule_id"] not in seen:
            seen.add(r["rule_id"])
            unique.append(r)
    return sorted(unique, key=lambda r: r["rule_id"])


def scan_pcap(path: str, trust_store: str | None = None) -> dict:
    """Run the engine over a PCAP. Raises FileNotFoundError / ValueError(3)."""
    from app.parsing.analysis import analyze_pcap
    try:
        analyses = analyze_pcap(path, trust_store)
    except FileNotFoundError:
        raise
    except Exception as e:
        raise ValueError(f"parse failure: {e}")
    sessions = []
    for sa in analyses:
        sessions.append({
            "session_id": sa.session_id, "protocol": sa.protocol,
            "five_tuple": sa.five_tuple,
            "tls_version": getattr(sa, "negotiated_version_name", None),
            "cipher": getattr(sa, "cipher", None),
            "findings": [{"rule_id": f.rule_id, "rule_name": f.rule_name,
                          "severity": f.severity, "title": f.title,
                          "description": f.description,
                          "reference": f.reference} for f in sa.findings],
        })
    return {"schema_version": SCHEMA_VERSION, "cipherpost_version": version(),
            "pcap": path, "sessions": sessions}


def load_baseline(path: str | None) -> list[dict]:
    if not path:
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("ignore", []) if isinstance(data, dict) else data


def load_suppressions(path: str | None):
    if not path:
        return []
    from types import SimpleNamespace
    with open(path) as f:
        data = json.load(f)
    items = data.get("suppressions", data) if isinstance(data, dict) else data
    out = []
    for i, s in enumerate(items or []):
        out.append(SimpleNamespace(id=f"file-{i}", rule_id=s.get("rule_id", "*"),
                                   scope=s.get("scope", {}), status="approved",
                                   expires_at="2099-01-01T00:00:00+00:00"))
    return out


def apply_filters(report: dict, baseline: list[dict], suppressions) -> dict:
    from app.proactive.suppressions import match_suppression
    ignored = {(b.get("rule_id"), b.get("five_tuple")) for b in baseline}
    out_sessions = []
    for sess in report["sessions"]:
        kept = []
        for f in sess["findings"]:
            if (f["rule_id"], sess["five_tuple"]) in ignored or (f["rule_id"], None) in ignored:
                continue
            m = match_suppression(f["rule_id"], {"five_tuple": sess["five_tuple"]}, suppressions)
            if m is not None:
                f = dict(f, suppressed=True, suppression_id=getattr(m, "id", None))
            kept.append(f)
        out_sessions.append(dict(sess, findings=kept))
    return dict(report, sessions=out_sessions)


def worst_severity(report: dict) -> str:
    worst, rank = "none", -1
    for sess in report["sessions"]:
        for f in sess["findings"]:
            if f.get("suppressed"):
                continue
            if SEV_ORDER.get(f["severity"], 0) > rank:
                worst, rank = f["severity"], SEV_ORDER.get(f["severity"], 0)
    return worst


def to_sarif(report: dict) -> dict:
    rules = {r["rule_id"]: r for r in rule_catalog()}
    sarif_rules, results = [], []
    for sess in report["sessions"]:
        for f in sess["findings"]:
            if f["rule_id"] not in rules:
                continue
            if f["rule_id"] not in [r["id"] for r in sarif_rules]:
                sev = f["severity"]
                sarif_rules.append({
                    "id": f["rule_id"], "name": f["rule_name"],
                    "shortDescription": {"text": f["title"]},
                    "fullDescription": {"text": f["description"]},
                    "helpUri": f.get("reference") or "",
                    "properties": {"severity": sev},
                    "defaultConfiguration": {
                        "level": "error" if sev in ("critical", "high")
                        else ("warning" if sev == "medium" else "note")},
                })
            results.append({
                "ruleId": f["rule_id"],
                "level": "error" if f["severity"] in ("critical", "high")
                else ("warning" if f["severity"] == "medium" else "note"),
                "message": {"text": f"{f['title']} [{sess['five_tuple']}]"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": report["pcap"]},
                    "region": {"startLine": 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {
                "name": "cipherpost", "version": report["cipherpost_version"],
                "rules": sarif_rules}}, "results": results}]}


def to_markdown(report: dict) -> str:
    lines = [f"# CipherPost scan: {report['pcap']}",
             f"_{len(report['sessions'])} sessions, engine v{report['cipherpost_version']}_", ""]
    for sess in report["sessions"]:
        lines.append(f"## {sess['protocol']} {sess['five_tuple']} "
                     f"(TLS {sess['tls_version'] or 'none'})")
        if not sess["findings"]:
            lines.append("- clean")
        for f in sess["findings"]:
            flag = " (suppressed)" if f.get("suppressed") else ""
            lines.append(f"- **{f['severity']}** {f['rule_id']}: {f['title']}{flag}")
        lines.append("")
    return "\n".join(lines)


def to_html(report: dict) -> str:
    import html as _h
    rows = []
    for sess in report["sessions"]:
        for f in sess["findings"]:
            rows.append(f"<tr><td>{_h.escape(sess['five_tuple'])}</td>"
                        f"<td>{_h.escape(f['rule_id'])}</td>"
                        f"<td>{_h.escape(f['severity'])}</td>"
                        f"<td>{_h.escape(f['title'])}</td></tr>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>CipherPost scan</title></head><body>"
            f"<h1>{_h.escape(report['pcap'])}</h1>"
            f"<table border='1'><tr><th>session</th><th>rule</th><th>severity</th>"
            f"<th>finding</th></tr>{''.join(rows)}</table></body></html>")


def cmd_scan(args) -> int:
    import os
    if not os.path.exists(args.pcap):
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = scan_pcap(args.pcap, trust_store=args.trust_store)
    except FileNotFoundError:
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_PARSE
    try:
        report = apply_filters(report, load_baseline(args.baseline),
                               load_suppressions(args.suppressions))
    except Exception as e:
        print(f"error: bad baseline/suppressions file: {e}", file=sys.stderr)
        return EXIT_USAGE
    fmt = (args.format or "json").lower()
    if fmt == "json":
        print(json.dumps(report, indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif(report), indent=2))
    elif fmt == "markdown":
        print(to_markdown(report))
    elif fmt == "html":
        print(to_html(report))
    else:
        print(f"error: unknown format {fmt}", file=sys.stderr)
        return EXIT_USAGE
    worst = worst_severity(report)
    threshold = (args.fail_on or "high").lower()
    if worst != "none" and SEV_ORDER.get(worst, 0) >= SEV_ORDER.get(threshold, 3):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_verify_domain(args) -> int:
    from app.proactive.mta_sts import check_domain
    out = check_domain(args.domain, refresh=True)
    print(json.dumps(out, indent=2, default=str))
    return EXIT_CLEAN if out.get("status") in ("ok", "not-published") else EXIT_FINDINGS


def cmd_rules(args) -> int:
    catalog = rule_catalog()
    if args.rules_cmd == "list":
        for r in catalog:
            print(f"{r['rule_id']:32} {r['severity']:8} {r['title']}")
        return EXIT_CLEAN
    if args.rules_cmd == "explain":
        for r in catalog:
            if r["rule_id"] == args.rule_id:
                print(json.dumps(r, indent=2))
                return EXIT_CLEAN
        print(f"error: unknown rule {args.rule_id}", file=sys.stderr)
        return EXIT_USAGE
    print("error: use `rules list|explain`", file=sys.stderr)
    return EXIT_USAGE


def build_parser() -> "argparse.ArgumentParser":
    import argparse
    ap = argparse.ArgumentParser(prog="cipherpost", description="Offline TLS forensics for email traffic")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="Analyze a PCAP file")
    sc.add_argument("pcap")
    sc.add_argument("--format", default="json", help="json|sarif|html|markdown")
    sc.add_argument("--fail-on", default="high", help="severity threshold for exit 1")
    sc.add_argument("--baseline", default=None, help="JSON baseline file to ignore accepted findings")
    sc.add_argument("--suppressions", default=None, help="JSON suppressions file (server scope format)")
    sc.add_argument("--trust-store", default=None)
    vd = sub.add_parser("verify-domain", help="MTA-STS/DANE posture for a domain")
    vd.add_argument("domain")
    rl = sub.add_parser("rules", help="List/explain detection rules")
    rl.add_argument("rules_cmd", nargs="?", default="list")
    rl.add_argument("rule_id", nargs="?")
    sub.add_parser("version", help="Print version")
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code != 0 else EXIT_CLEAN
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "verify-domain":
        return cmd_verify_domain(args)
    if args.cmd == "rules":
        return cmd_rules(args)
    if args.cmd == "version":
        print(version())
        return EXIT_CLEAN
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
