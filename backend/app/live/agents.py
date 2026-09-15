"""
Track 3: capture-agent registration + heartbeat.

Each capture worker identifies as an agent (`CIPHERPOST_AGENT_ID`, default
`<hostname>/<iface>`) and heartbeats into Redis (`cipherpost:agents:<id>`,
TTL 3x interval) with its interface, mode, and throughput counters. The
dashboard's agents strip and GET /api/v1/agents read these keys, so ops can
see which network segments/sites are covered and whether an agent went quiet.

Multiple agents publish to the same SESSION_STREAM; analysis workers consume
via a shared consumer group (XREADGROUP), so scaling analyzers never
double-processes a session. See test_track3_agents.py for the proof.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time

log = logging.getLogger("cipherpost.live.agents")

AGENT_KEY_PREFIX = "cipherpost:agents"


def default_agent_id(iface: str) -> str:
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return f"{host}/{iface}"


def agent_key(agent_id: str) -> str:
    return f"{AGENT_KEY_PREFIX}:{agent_id}"


class AgentHeartbeat:
    """Background heartbeat writer. Stops with the worker."""

    def __init__(self, r, agent_id: str, interval: float = 10.0, ttl: float = 30.0):
        self.r = r
        self.agent_id = agent_id
        self.interval = interval
        self.ttl = ttl
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self.info: dict = {}
        self.stats_fn = None  # () -> dict, attached by the worker

    def start(self, info: dict | None = None, stats_fn=None):
        if info:
            self.info.update(info)
        if stats_fn:
            self.stats_fn = stats_fn
        if not self._t.is_alive():
            self._stop.clear()
            self._t = threading.Thread(target=self._loop, daemon=True)
            self._t.start()
        self.beat()

    def beat(self):
        payload = {"agent_id": self.agent_id, "ts": time.time(), **self.info}
        if self.stats_fn:
            try:
                payload["stats"] = self.stats_fn()
            except Exception as e:
                payload["stats_error"] = str(e)
        try:
            self.r.setex(agent_key(self.agent_id), int(self.ttl), json.dumps(payload))
        except Exception as e:
            log.debug("agent heartbeat failed: %s", e)

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.beat()

    def stop(self):
        self._stop.set()
        try:
            self.r.delete(agent_key(self.agent_id))
        except Exception:
            pass


def list_agents(r, max_age_seconds: float = 60.0) -> list[dict]:
    """Agents with a recent heartbeat; stale ones flagged offline."""
    out = []
    try:
        keys = r.keys(f"{AGENT_KEY_PREFIX}:*")
    except Exception:
        return out
    now = time.time()
    for k in keys:
        try:
            raw = r.get(k)
            if not raw:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode()
            info = json.loads(raw)
            age = now - float(info.get("ts", 0))
            info["age_seconds"] = round(age, 1)
            info["online"] = age <= max_age_seconds
            out.append(info)
        except Exception:
            continue
    return sorted(out, key=lambda a: a.get("agent_id", ""))
