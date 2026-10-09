"""Audit helper (Task 5): print every real capture with its source config and
expected findings, so a human can compare labels against configuration.

Usage: PYTHONPATH=backend python scripts/audit_labels.py [manifest]
Exits 0 always (audit aid, not a gate); flags provenance gaps inline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit real-capture labels vs config")
    ap.add_argument("manifest", nargs="?",
                    default="tests/real/manifest.json")
    args = ap.parse_args(argv)
    man = json.loads(Path(args.manifest).read_text())
    print(f"manifest version {man.get('version')}; "
          f"{len(man.get('captures', []))} captures\n")
    gaps = 0
    for e in man.get("captures", []):
        print(f"== {e.get('pcap')}")
        print(f"   license: {e.get('license', '?')[:100]}")
        sc = e.get("source_config") or {}
        for k in ("harness", "driver", "certs", "scenario", "evidence"):
            print(f"   config.{k}: {sc.get(k)}")
        prov = e.get("provenance", "provenance incomplete")
        print(f"   provenance: {prov}")
        if "incomplete" in prov and "partial" not in prov:
            gaps += 1
        print(f"   source: {(e.get('source') or '')[:130]}")
        for f in e.get("expected_findings", []):
            print(f"   expect session={f.get('session')} "
                  f"{f.get('rule_id')} present={f.get('present')} "
                  f"-- {f.get('notes', '')[:110]}")
        print()
    print(f"provenance gaps (incomplete, non-partial): {gaps}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
