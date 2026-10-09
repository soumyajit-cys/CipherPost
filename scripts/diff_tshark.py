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


def _layers(pkt: dict) -> dict:
    # tshark -T json nests fields under _source.layers (values are lists).
    # The old code read pkt["layers"] and silently got nothing.
    src = pkt.get("_source") or {}
    return src.get("layers") or {}


def _one(layers: dict, field: str):
    vals = layers.get(field) or []
    return vals[0] if vals else None


def tshark_tls(pcap: Path) -> list[dict]:
    # Extract handshake fields per packet via tshark JSON. Separate
    # ClientHello (type 1, offers) from ServerHello (type 2, selected):
    # tls.handshake.ciphersuite is the ServerHello's selected cipher,
    # tls.handshake.ciphersuites the ClientHello offer list.
    cmd = ["tshark", "-r", str(pcap), "-T", "json",
           "-e", "tls.handshake.type",
           "-e", "tls.handshake.version",
           "-e", "tls.handshake.ciphersuite",
           "-e", "tls.handshake.ciphersuites",
           "-e", "tls.handshake.extensions_supported_version",
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
        layers = _layers(pkt)
        rows.append({
            "hs_type": _one(layers, "tls.handshake.type"),
            "tls_version": _one(layers, "tls.handshake.version"),
            "cipher": _one(layers, "tls.handshake.ciphersuite"),
            "ciphers": layers.get("tls.handshake.ciphersuites") or [],
            "supported_version": _one(layers, "tls.handshake.extensions_supported_version"),
            "subjects": layers.get("x509sat.printableString") or [],
            "sni": _one(layers, "tls.handshake.extensions_server_name"),
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


def _hex_int(value) -> int | None:
    """Parse tshark hex ("0x1302") or decimal strings to int; None if unknown."""
    if value is None:
        return None
    try:
        s = str(value).strip().lower()
        return int(s, 16) if s.startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def _cipher_name(iana: int | None) -> str | None:
    if iana is None:
        return None
    try:
        from app.parsing.handshake import lookup_cipher
        meta = lookup_cipher(iana)
        return meta.name if meta else None
    except Exception:
        return None


def diff_one(pcap: Path) -> dict:
    ours = ours_tls(pcap)
    theirs = tshark_tls(pcap)
    disagreements: list[str] = []
    if theirs and isinstance(theirs, list) and theirs and "error" in (theirs[0] or {}):
        return {"pcap": str(pcap), "skip": theirs[0]["error"], "disagreements": []}
    # ServerHello packets: negotiated (version, cipher) pairs from tshark.
    # supported_versions ext carries the real 1.3 version; the legacy
    # handshake.version field stays 0x0303, so accept either.
    their_pairs = set()
    for r in theirs:
        if str(r.get("hs_type")) != "2":
            continue
        ver = _hex_int(r.get("supported_version"))
        if ver is None:
            ver = _hex_int(r.get("tls_version"))
        name = _cipher_name(_hex_int(r.get("cipher")))
        if ver is not None or name is not None:
            their_pairs.add((ver, name))
    our_pairs = set()
    for r in ours:
        ver = r.get("tls_version")
        ver = ver if isinstance(ver, int) else _hex_int(ver)
        if ver is not None or r.get("cipher"):
            our_pairs.add((ver, r.get("cipher")))
    for ver, name in sorted(our_pairs, key=str):
        if name is None:
            continue
        match = any(tv == ver and (tn == name or tn is None)
                    for tv, tn in their_pairs)
        if not match:
            if not their_pairs:
                disagreements.append(
                    f"tshark decoded no ServerHello while we did: ours={sorted(our_pairs, key=str)[:3]}")
            else:
                disagreements.append(
                    f"session (tls={ver}, cipher={name}) not in tshark ServerHellos: "
                    f"tshark={sorted(their_pairs, key=str)[:6]}")
    for ver, name in sorted(their_pairs, key=str):
        if name is None:
            continue
        if not any(ov == ver and oc == name for ov, oc in our_pairs):
            disagreements.append(
                f"tshark ServerHello (tls={ver}, cipher={name}) missing from our sessions")
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
