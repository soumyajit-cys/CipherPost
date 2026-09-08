"""
Capture worker: attaches to interface (scapy sniff) or replays pcap(s),
streams packets through RollingRawStore + LiveReassembler, emits completed
Sessions onto Redis Stream `cipherpost:sessions`.

Runs as a long-lived process. Handles SIGTERM/SIGINT gracefully, bounds
memory via LiveReassembler caps, and drops/samples when overwhelmed.
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

import redis

from app.core.config import settings
from app.live.packets import Packet, bpf_port_filter, packet_from_scapy, iter_pcap_packets
from app.live.reassembly import LiveReassembler
from app.live.retention import RollingRawStore
from app.live.serialize import session_to_payload
from app.live.metrics import Gossiper
from app.live import streams as bus

log = logging.getLogger("cipherpost.live.capture")

def _port_set() -> set[int]:
    raw = (settings.LIVE_BPF_PORTS + "," + settings.LIVE_EXTRA_PORTS).strip(",")
    out = set()
    for p in raw.split(","):
        p=p.strip()
        if p.isdigit():
            out.add(int(p))
    return out

ALLOWED_PORTS = _port_set()

def _bpf() -> str:
    ports = sorted(ALLOWED_PORTS)
    return bpf_port_filter(ports)

class CaptureWorker:
    def __init__(self, iface: str | None = None, redis_client=None,
                 replay_paths: list[str] | None = None,
                 replay_speed: float = 0.0,
                 promisc: bool | None = None):
        self.iface = iface or settings.LIVE_IFACE
        self.replay_paths = replay_paths
        self.replay_speed = replay_speed if replay_speed else settings.LIVE_REPLAY_SPEED
        self.promisc = promisc if promisc is not None else settings.LIVE_PROMISC
        self._stop = threading.Event()
        self.r = redis_client or redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        # retry redis connection
        self.store = RollingRawStore(settings.RAW_CAPTURE_DIR, settings.RAW_RETENTION_SECONDS, settings.RAW_SEGMENT_SECONDS)
        self.asm = LiveReassembler(
            idle_timeout=settings.LIVE_IDLE_TIMEOUT,
            max_sessions=settings.LIVE_MAX_SESSIONS,
            max_buffer_bytes=settings.LIVE_MAX_SESSION_BUFFER_BYTES,
        )
        self.gossip = Gossiper(self.r, "capture", interval=5)
        self._packets_seen = 0
        self._sessions_emitted = 0
        self._lock = threading.Lock()

    def _signal(self, signum, frame):
        log.info("signal %s received, shutting down", signum)
        self._stop.set()

    def _emit_sessions(self, sessions):
        for sess in sessions:
            if sess is None:
                continue
            try:
                bus.publish_session(self.r, sess)
                bus.notify(self.r, "sessions", "session", {
                    "five_tuple": sess.five_tuple,
                    "protocol": sess.protocol.value,
                    "closed_by": getattr(sess, "closed_by", "unknown"),
                    "tls_bytes": len(sess.tls_segment),
                })
                self._sessions_emitted += 1
                self.gossip.counters.inc("sessions_emitted")
            except Exception as e:
                log.warning("publish session failed: %s", e)
                self.gossip.counters.inc("publish_errors")

    def _handle_packet(self, pkt: Packet):
        # port filter at python level (BPF already does, but replay path needs it)
        if pkt.sport not in ALLOWED_PORTS and pkt.dport not in ALLOWED_PORTS:
            self.gossip.counters.inc("filtered_out")
            return
        self._packets_seen += 1
        self.gossip.counters.inc("packets_seen")
        # retention: write raw frame (only for allowed ports to save space)
        if pkt.raw:
            try:
                ref = self.store.write(pkt.ts, pkt.raw)
                pkt.raw_ref = ref
            except Exception as e:
                log.debug("store write failed: %s", e)
        try:
            self.asm.feed_packet(pkt)
        except Exception as e:
            log.warning("reassembly feed failed: %s", e)

    def _drain(self):
        now = time.time()
        sessions = self.asm.tick(now)
        if sessions:
            self._emit_sessions(sessions)
        # gossip active
        self.gossip.counters.set("sessions_active", self.asm.stats.active)
        self.gossip.counters.set("sessions_dropped", self.asm.stats.evicted)

    def run_live(self):
        log.info("capture live on iface=%s bpf='%s' promisc=%s", self.iface, _bpf(), self.promisc)
        self.store.start()
        self.gossip.start()
        # signal handling
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass  # not in main thread
        # sweeper thread
        def sweeper():
            while not self._stop.wait(settings.LIVE_DRAIN_INTERVAL):
                try:
                    self._drain()
                except Exception as e:
                    log.warning("drain error: %s", e)
        t = threading.Thread(target=sweeper, daemon=True)
        t.start()

        try:
            from scapy.all import sniff
        except ImportError as e:
            log.error("scapy not available: %s", e)
            raise

        while not self._stop.is_set():
            try:
                sniff(
                    iface=self.iface,
                    prn=lambda p: self._handle_packet(packet_from_scapy(p)) if packet_from_scapy(p) else None,
                    store=False,
                    filter=_bpf(),
                    promisc=self.promisc,
                    timeout=settings.LIVE_DRAIN_INTERVAL,
                    stop_filter=lambda p: self._stop.is_set(),
                )
            except PermissionError as e:
                log.error("capture permission denied (need CAP_NET_RAW/CAP_NET_ADMIN or --net=host): %s", e)
                log.error("hint: run with cap_add: [NET_RAW, NET_ADMIN] and network_mode: host for SPAN/TAP")
                time.sleep(5)
            except Exception as e:
                if self._stop.is_set():
                    break
                log.warning("sniff error: %s", e)
                time.sleep(1)

        log.info("live capture stopping, final drain...")
        self._drain()
        self.gossip.stop()
        self.store.stop()
        log.info("capture stopped: packets=%d sessions=%d", self._packets_seen, self._sessions_emitted)

    def run_replay(self, loop: bool = False):
        """Replay mode: iterate pcap files through same pipeline."""
        assert self.replay_paths
        log.info("replay mode: %s speed=%s loop=%s", self.replay_paths, self.replay_speed, loop)
        self.store.start()
        self.gossip.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass
        def do_once():
            for path in self.replay_paths:
                p = Path(path)
                files = [p] if p.is_file() else sorted(p.glob("*.pcap*"))
                for f in files:
                    if self._stop.is_set():
                        return
                    log.info("replaying %s", f)
                    prev_ts = None
                    for pkt in iter_pcap_packets(str(f)):
                        if self._stop.is_set():
                            return
                        if self.replay_speed > 0 and prev_ts is not None:
                            delta = pkt.ts - prev_ts
                            if delta > 0:
                                time.sleep(delta / self.replay_speed)
                        prev_ts = pkt.ts
                        self._handle_packet(pkt)
                        # periodic drain every 200 packets
                        if self._packets_seen % 200 == 0:
                            self._drain()
                    self._drain()
                    log.info("replay %s done: packets=%d emitted=%d", f, self._packets_seen, self._sessions_emitted)
        if loop:
            while not self._stop.is_set():
                do_once()
                time.sleep(1)
        else:
            do_once()
        self._drain()
        self.gossip.stop()
        self.store.stop()
        log.info("replay finished")

    def run(self):
        if self.replay_paths:
            self.run_replay()
        else:
            self.run_live()

def main(argv=None):
    ap = argparse.ArgumentParser(description="CipherPost capture worker")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--replay", nargs="*", default=None, help="pcap file(s) or dir for replay mode")
    ap.add_argument("--speed", type=float, default=0.0, help="replay speed multiplier (0=fast)")
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    w = CaptureWorker(iface=args.iface, replay_paths=args.replay, replay_speed=args.speed)
    w.replay_paths = args.replay
    if args.loop:
        # reuse run_replay loop flag via wrapper
        orig = w.run_replay
        def patched(loop=False):
            return orig(loop=True)
        w.run_replay = patched
    w.run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
