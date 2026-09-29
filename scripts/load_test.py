"""Load/soak measurement: replay a PCAP, report real throughput numbers.

Measures what actually happened on this machine (no estimates):
  - packets/sec and sessions/sec at the requested replay rate
  - packet-to-alert latency (first packet of a session -> analysis complete)
    as p50/p95/p99
  - peak RSS of this process

Usage:
  PYTHONPATH=backend python scripts/load_test.py tests/fixtures/smtp_tls12_starttls.pcap
  PYTHONPATH=backend python scripts/load_test.py tests/fixtures/ --rate 5000 --duration 30

Publish the output (plus machine spec) in docs/sizing.md. Only include
numbers you actually measured; mark anything else as an estimate.
"""
from __future__ import annotations

import argparse
import glob
import resource
import statistics
import sys
import time


def _rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def run(pcaps: list[str], rate: float, duration: float) -> dict:
    sys.path.insert(0, "backend")
    from app.live.packets import iter_pcap_packets
    from app.live.reassembly import LiveReassembler
    from app.parsing.analysis import analyze_session

    asm = LiveReassembler()
    latencies: list[float] = []
    session_first: dict[str, float] = {}
    n_packets = 0
    n_sessions = 0
    n_findings = 0
    t_start = time.time()
    deadline = t_start + duration if duration > 0 else float("inf")
    min_interval = 1.0 / rate if rate and rate > 0 else 0.0
    last = t_start
    for path in pcaps:
        for pkt in iter_pcap_packets(path):
            if time.time() > deadline:
                break
            if min_interval:
                now = time.time()
                wait = min_interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
                last = time.time()
            n_packets += 1
            try:
                asm.feed_packet(pkt)
            except Exception:
                pass
            ft = f"{pkt.src}:{pkt.sport}-{pkt.dst}:{pkt.dport}"
            session_first.setdefault(ft, time.time())
            for sess in asm.tick(time.time()):
                n_sessions += 1
                t0 = time.time()
                try:
                    sa = analyze_session(sess)
                    n_findings += len(sa.findings)
                except Exception:
                    pass
                first = session_first.pop(sess.five_tuple, t0)
                latencies.append(t0 - first + (time.time() - t0))
    for sess in asm.tick(time.time() + 9999) + asm.drain():
        n_sessions += 1
        t0 = time.time()
        try:
            from app.parsing.analysis import analyze_session as _an
            sa = _an(sess)
            n_findings += len(sa.findings)
        except Exception:
            pass
        first = session_first.pop(sess.five_tuple, t0)
        latencies.append(time.time() - first)
    elapsed = max(time.time() - t_start, 1e-6)
    latencies.sort()
    def pct(p: float) -> float | None:
        if not latencies:
            return None
        k = min(len(latencies) - 1, int(p / 100 * len(latencies)))
        return latencies[k]
    return {"pcaps": pcaps, "packets": n_packets, "sessions": n_sessions,
            "findings": n_findings, "elapsed_s": round(elapsed, 2),
            "packets_per_s": round(n_packets / elapsed, 1),
            "sessions_per_s": round(n_sessions / elapsed, 1),
            "latency_p50_s": pct(50), "latency_p95_s": pct(95),
            "latency_p99_s": pct(99), "peak_rss_mb": round(_rss_mb(), 1)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CipherPost load measurement")
    ap.add_argument("pcap", help=".pcap file or directory")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="packets/sec, 0 = as fast as possible")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="max seconds, 0 = whole input once")
    args = ap.parse_args(argv)
    import pathlib
    p = pathlib.Path(args.pcap)
    pcaps = sorted(str(f) for f in (p.glob("*.pcap*") if p.is_dir() else [p]))
    if not pcaps:
        print("no pcaps found", file=sys.stderr)
        return 1
    rep = run(pcaps, args.rate, args.duration)
    import json
    print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
