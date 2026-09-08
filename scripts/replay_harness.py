"""
Replay harness: feeds recorded PCAPs through the live capture pipeline.

Two modes:
  --mode direct  : python iterator directly into LiveReassembler + analyze (no network, deterministic, for pytest)
  --mode capture : via CaptureWorker replay (writes to Redis stream, needs redis+db, closest to live)
  --mode tcpreplay: shell out to tcpreplay on an interface (requires tcpreplay + CAP_NET_RAW)

Default is direct, which is the regression suite used in tests.
"""
from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path

def replay_direct(pcap: str, trust_bundle: str | None = None):
    """Direct pipeline: pcap -> LiveReassembler -> analyze_session -> ML (scoring). Returns (sessions, analyses, scores)."""
    from app.live.packets import iter_pcap_packets
    from app.live.reassembly import LiveReassembler
    from app.parsing.analysis import analyze_session
    from app.ml.ml_engine import SessionScorer

    asm = LiveReassembler(idle_timeout=5, max_sessions=8192, max_buffer_bytes=2*1024*1024)
    for pkt in iter_pcap_packets(pcap):
        asm.feed_packet(pkt)
    # final sweep with far-future time to force idle close
    sessions = asm.tick(time.time()+9999)
    # also drain any fin-closed left
    sessions += asm.drain()
    analyses = [analyze_session(s, trust_store=trust_bundle) for s in sessions]
    scorer = SessionScorer()
    if analyses:
        scorer.train(analyses)
        scores = scorer.score_batch(analyses)
    else:
        scores = []
    return sessions, analyses, scores

def replay_via_capture(pcap: str, speed: float = 0):
    from app.live.capture import CaptureWorker
    w = CaptureWorker(replay_paths=[pcap], replay_speed=speed)
    w.run()

def main(argv=None):
    ap = argparse.ArgumentParser(description="CipherPost replay harness")
    ap.add_argument("pcap", help="pcap file or directory")
    ap.add_argument("--mode", choices=["direct","capture","tcpreplay"], default="direct")
    ap.add_argument("--trust", default=None)
    ap.add_argument("--speed", type=float, default=0)
    ap.add_argument("--iface", default="lo")
    args = ap.parse_args(argv)
    p = Path(args.pcap)
    files = [str(p)] if p.is_file() else [str(x) for x in sorted(p.glob("*.pcap*"))]
    if args.mode == "direct":
        total_sess = 0
        for f in files:
            sess, analyses, scores = replay_direct(f, args.trust)
            print(f"{f}: {len(sess)} sessions, {sum(len(a.findings) for a in analyses)} findings")
            total_sess += len(sess)
        print(f"total sessions: {total_sess}")
    elif args.mode == "capture":
        for f in files:
            replay_via_capture(f, args.speed)
    elif args.mode == "tcpreplay":
        import subprocess
        for f in files:
            print(f"tcpreplay {f} -> {args.iface}")
            subprocess.run(["tcpreplay", "-i", args.iface, f], check=False)
    return 0

if __name__ == "__main__":
    sys.exit(main())
