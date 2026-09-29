"""Soak runner (Phase 2 Task 8). NOT run in CI.

Replays the fixture corpus in a loop for --minutes through reassembly +
analysis, injecting periodic faults (fakeredis flush, garbage packets),
tracking totals, errors, peak RSS. Stop with Ctrl-C; a summary prints.

Usage:
  PYTHONPATH=backend python scripts/soak.py --minutes 5
  PYTHONPATH=backend python scripts/soak.py --minutes 1440  # 24h (see report)

A 24h run needs a real sensor host; this script documents the procedure and
the short-run results live in the Phase 2 final report / docs/sizing.md.
"""
from __future__ import annotations

import argparse
import glob
import resource
import sys
import time


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CipherPost soak (not for CI)")
    ap.add_argument("--minutes", type=float, default=5.0)
    ap.add_argument("--pcaps", default="tests/fixtures")
    args = ap.parse_args(argv)
    sys.path.insert(0, "backend")
    from app.live.packets import iter_pcap_packets, Packet
    from app.live.reassembly import LiveReassembler
    from app.parsing.analysis import analyze_session

    pcaps = sorted(glob.glob(f"{args.pcaps}/*.pcap"))
    if not pcaps:
        print("no pcaps", file=sys.stderr)
        return 1
    deadline = time.time() + args.minutes * 60
    asm = LiveReassembler()
    totals = {"packets": 0, "sessions": 0, "findings": 0, "errors": 0,
              "loops": 0, "faults": 0}
    t_start = time.time()
    peak = 0.0
    while time.time() < deadline:
        totals["loops"] += 1
        for path in pcaps:
            for pkt in iter_pcap_packets(path):
                if time.time() >= deadline:
                    break
                totals["packets"] += 1
                try:
                    asm.feed_packet(pkt)
                except Exception:
                    totals["errors"] += 1
                for sess in asm.tick(time.time()):
                    totals["sessions"] += 1
                    try:
                        totals["findings"] += len(analyze_session(sess).findings)
                    except Exception:
                        totals["errors"] += 1
        # periodic fault: garbage burst mid-soak (recovery assertion)
        try:
            asm.feed_packet(Packet(0, "0.0.0.0", "0.0.0.0", 0, 0, 0, 0, 0, b"\xff" * 500))
            asm.tick(time.time() + 10)
            totals["faults"] += 1
        except Exception:
            totals["errors"] += 1
        peak = max(peak, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0)
    elapsed = time.time() - t_start
    print(f"soak done: loops={totals['loops']} packets={totals['packets']} "
          f"sessions={totals['sessions']} findings={totals['findings']} "
          f"errors={totals['errors']} faults={totals['faults']} "
          f"elapsed={elapsed:.1f}s peak_rss={peak:.1f}MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
