"""cipherpost-agent main loop (Phase 3 Task 3).

Config precedence: CLI flags > env (CIPHERPOST_AGENT_*) > JSON config file.
Without --iface/--replay it exits with usage (capture needs privileges).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("cipherpost.agent")


def load_config(path: str | None) -> dict:
    cfg: dict = {}
    if path:
        try:
            with open(path) as f:
                cfg.update(json.load(f))
        except Exception as e:
            raise ValueError(f"bad agent config {path}: {e}")
    env_map = {
        "CIPHERPOST_AGENT_ID": "agent_id",
        "CIPHERPOST_AGENT_ORG_ID": "org_id",
        "CIPHERPOST_AGENT_TOKEN": "token",
        "CIPHERPOST_AGENT_SERVER": "server",
        "CIPHERPOST_AGENT_QUEUE": "queue_path",
        "CIPHERPOST_AGENT_IFACE": "iface",
        "CIPHERPOST_AGENT_CA": "ca_bundle",
        "CIPHERPOST_AGENT_PIN": "tls_pin",
        "CIPHERPOST_AGENT_ADDR_MODE": "addr_mode",
        "CIPHERPOST_AGENT_HEALTH_PORT": "health_port",
    }
    for env, key in env_map.items():
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    cfg.setdefault("addr_mode", "full")
    cfg.setdefault("queue_path", "/var/lib/cipherpost/agent-queue.jsonl")
    cfg.setdefault("health_port", 9099)
    return cfg


class Agent:
    def __init__(self, cfg: dict, replay_paths=None):
        from app.agent.queue import DiskQueue
        from app.agent.shipper import Shipper
        self.cfg = cfg
        self.replay_paths = replay_paths
        self._stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, lambda *a: self._stop.set())
            except ValueError:
                pass
        token = cfg.get("token", "")
        server = (cfg.get("server", "") or "").rstrip("/")
        if not token or not server:
            raise ValueError("agent needs server + token (config file or env)")
        self.queue = DiskQueue(cfg["queue_path"])
        self.shipper = Shipper(server, token, ca_bundle=cfg.get("ca_bundle"),
                               pin=cfg.get("tls_pin"))
        self.agent_id = cfg.get("agent_id") or "agent"
        self.addr_mode = cfg.get("addr_mode", "full")
        self.emitted = 0
        self.shipped = 0
        self._health = None

    # -- health/metrics endpoint -------------------------------------------
    def start_health(self) -> None:
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body, code = b'{"status":"ok"}', 200
                if self.path == "/metrics":
                    body = json.dumps({
                        "queue_depth": agent.queue.depth(),
                        "emitted": agent.emitted,
                        "shipped": agent.shipped,
                        "queue_dropped": agent.queue.dropped,
                        "token_revoked": agent.shipper.revoked,
                    }).encode()
                elif self.path != "/healthz":
                    code, body = 404, b'{"error":"not found"}'
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._health = ThreadingHTTPServer(("127.0.0.1", int(self.cfg["health_port"])), Handler)
        threading.Thread(target=self._health.serve_forever, daemon=True).start()

    def stop_health(self) -> None:
        try:
            if self._health:
                self._health.shutdown()
        except Exception:
            pass

    # -- pipeline -----------------------------------------------------------
    def _handle_session(self, sess) -> None:
        from app.agent import meta as _meta
        try:
            from app.parsing.analysis import analyze_session
            sa = analyze_session(sess)
        except Exception as e:
            log.debug("agent analysis skipped: %s", e)
            return
        try:
            item = _meta.session_to_metadata(sess, sa, agent_id=self.agent_id,
                                             addr_mode=self.addr_mode)
            self.queue.append(item)
            self.emitted += 1
        except Exception as e:
            log.debug("agent metadata skipped: %s", e)

    def _ship_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.shipper.revoked:
                    time.sleep(30)
                    continue
                start, batch = self.queue.read_batch(limit=100)
                if not batch:
                    time.sleep(2)
                    continue
                self.shipper.send_batch(batch)
                self.queue.ack(start + len(batch))
                self.shipped += len(batch)
            except Exception as e:
                log.debug("ship failed, will retry: %s", e)
                time.sleep(5)

    def run_replay(self, paths) -> int:
        """Offline replay path (tests + backfill): no server needed for parse."""
        from app.live.packets import iter_pcap_packets
        from app.live.reassembly import LiveReassembler
        import time as _t
        asm = LiveReassembler()
        n = 0
        for path in paths:
            for pkt in iter_pcap_packets(path):
                if self._stop.is_set():
                    return n
                try:
                    asm.feed_packet(pkt)
                except Exception:
                    continue
                n += 1
                for sess in asm.tick(_t.time()):
                    self._handle_session(sess)
        for sess in asm.tick(_t.time() + 9999) + asm.drain():
            self._handle_session(sess)
        return n

    def run(self) -> int:
        self.start_health()
        shipper = threading.Thread(target=self._ship_loop, daemon=True)
        shipper.start()
        try:
            if self.replay_paths:
                self.run_replay(self.replay_paths)
                # drain the queue once, then exit (one-shot backfill)
                deadline = time.time() + 300
                while self.queue.depth() and time.time() < deadline and not self._stop.is_set():
                    time.sleep(2)
            else:
                self._run_live()
        finally:
            self._stop.set()
            self.stop_health()
        log.info("agent stopped: emitted=%d shipped=%d queued=%d",
                 self.emitted, self.shipped, self.queue.depth())
        return 0

    def _run_live(self) -> None:
        from app.live.capture import CaptureWorker  # local import: needs scapy
        w = CaptureWorker(iface=self.cfg.get("iface", "eth0"))
        # Reuse the shared sniffer; redirect its sessions to metadata.
        orig = w._emit_sessions

        def _to_meta(sessions):
            from app.live.packets import Packet  # noqa (keeps import graph honest)
            for sess in sessions or []:
                if sess is None:
                    continue
                try:
                    from app.parsing.analysis import analyze_session
                    sa = analyze_session(sess)
                    from app.agent import meta as _meta
                    self.queue.append(_meta.session_to_metadata(
                        sess, sa, agent_id=self.agent_id, addr_mode=self.addr_mode))
                    self.emitted += 1
                except Exception as e:
                    log.debug("agent session skipped: %s", e)

        w._emit_sessions = _to_meta
        w.run_live()


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="CipherPost standalone sensor agent")
    ap.add_argument("--config", default=None)
    ap.add_argument("--server", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--replay", nargs="*", default=None)
    ap.add_argument("--health-port", type=int, default=None)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        cfg = load_config(args.config)
    except ValueError as e:
        print(str(e))
        return 2
    for k, v in (("server", args.server), ("token", args.token),
                 ("iface", args.iface), ("health_port", args.health_port)):
        if v is not None:
            cfg[k] = v
    try:
        agent = Agent(cfg, replay_paths=args.replay)
    except ValueError as e:
        print(str(e))
        return 2
    return agent.run()


if __name__ == "__main__":
    raise SystemExit(main())
