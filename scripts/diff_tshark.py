"""Differential check: our parser vs tshark (if installed).

For each PCAP, compares TLS version, cipher suite, and certificate subjects
from CipherPost's parser against tshark's dissection, printing disagreements.

Usage:
  python scripts/diff_tshark.py tests/fixtures/smtp_tls12_starttls.pcap
  python scripts/diff_tshark.py tests/fixtures/ --limit 5

If tshark is missing, exits 0 with a clear skip message (not a failure).
This is a diagnostic aid, not a CI gate.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def have_tshark() -> bool:
    return shutil.which("tshark") is not None


def tshark_tls(pcap: Path) -> list[dict]:
    # Extract handshake fields per TLS record via tshark JSON.
    cmd = ["tshark", "-r", str(pcap), "-T", "json",
           "-e", "tls.handshake.version",
           "-e", "tls.handshake.ciphersuite",
           "-e", "x509sat.printableString",
           "-e", "tls.handshake.extensions_server_name"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        return [{"error": f"tshark failed: {e}"}]
    if out.returncode != 0:
        return [{"error": out.stderr.strip()[:500]}]
    try:
        data = json.loads(out.stdout or "[]")
    except Exception as e:
        return [{"error": f"tshark JSON parse failed: {e}"}]
    rows = []
    for pkt in data:
        layers = pkt.get("layers", {})
        rows.append({
            "tls_version": layers.get("tls.handshake.version"),
            "cipher": layers.get("tls.handshake.ciphersuite"),
            "subjects": layers.get("x509sat.printableString"),
            "sni": layers.get("tls.handshake.extensions_server_name"),
        })
    return rows


def ours_tls(pcap: Path) -> list[dict]:
    sys.path.insert(0, "backend")
    from app.parsing.analysis import analyze_pcap
    analyses = analyze_pcap(str(pcap))
    rows = []
    for a in analyses:
        cert_cns = []
        for c in (getattr(a, "certs", None) or []):
            cert_cns.append(getattr(c, "subject_cn", ""))
        rows.append({
            "session": getattr(a, "session_id", ""),
            "tls_version": getattr(a, "tls_version", None),
            "cipher": getattr(a, "cipher", None),
            "cert_cns": cert_cns,
        })
    return rows


def diff_one(pcap: Path) -> dict:
    ours = ours_tls(pcap)
    theirs = tshark_tls(pcap)
    disagreements: list[str] = []
    if theirs and isinstance(theirs, list) and theirs and "error" in (theirs[0] or {}):
        return {"pcap": str(pcap), "skip": theirs[0]["error"], "disagreements": []}
    # Heuristic comparison: collect version/cipher strings from both sides.
    our_versions = sorted({str(r.get("tls_version")) for r in ours})
    their_versions = sorted({str(v) for r in theirs for v in (r.get("tls_version") or []) if v})
    if our_versions and their_versions and not set(our_versions) & set(their_versions):
        # versions are encoded differently (hex vs dotted); only flag if clearly disjoint
        disagreements.append(f"version sets disjoint: ours={our_versions} tshark={their_versions[:5]}")
    our_ciphers = sorted({str(r.get("cipher")) for r in ours if r.get("cipher")})
    their_ciphers = sorted({str(v) for r in theirs for v in (r.get("cipher") or []) if v})
    # Cipher names differ in format (IANA vs OpenSSL); report counts only.
    if our_ciphers and not their_ciphers:
        disagreements.append(f"tshark found no ciphers but we did: {our_ciphers[:3]}")
    if their_ciphers and not our_ciphers:
        disagreements.append(f"we found no ciphers but tshark did: {their_ciphers[:3]}")
    our_cns = sorted({c for r in ours for c in r.get("cert_cns", []) if c})
    their_subjects = sorted({str(v) for r in theirs for v in (r.get("subjects") or []) if v})
    for cn in our_cns:
        if cn and not any(cn in s for s in their_subjects):
            disagreements.append(f"cert CN {cn!r} not seen in tshark subjects")
            break
    return {"pcap": str(pcap), "ours": ours, "tshark_rows": len(theirs),
            "disagreements": disagreements}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Diff our TLS parse vs tshark")
    ap.add_argument("pcap", help=".pcap file or directory")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)
    if not have_tshark():
        print("diff_tshark: tshark not installed — skipping (install wireshark-cli to enable)")
        return 0
    p = Path(args.pcap)
    pcaps = sorted(p.glob("*.pcap")) if p.is_dir() else [p]
    if args.limit:
        pcaps = pcaps[: args.limit]
    any_dis = False
    for pc in pcaps:
        res = diff_one(pc)
        if res.get("skip"):
            print(f"{pc}: skip ({res['skip'][:120]})")
            continue
        if res["disagreements"]:
            any_dis = True
            print(f"{pc}: DISAGREEMENTS")
            for d in res["disagreements"]:
                print(f"  - {d}")
        else:
            print(f"{pc}: agree (sessions={len(res['ours'])} tshark_rows={res['tshark_rows']})")
    return 0  # informational, never fails CI


if __name__ == "__main__":
    raise SystemExit(main())
