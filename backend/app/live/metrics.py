"""
Cross-process metrics gossip.

Each long-running worker (capture/analysis/alerts) keeps a small local counter
dict and periodically writes a snapshot into Redis with a TTL. The API's
/metrics endpoint merges every worker's snapshot into the Prometheus registry
on each scrape, giving a single coherent view without MULTIPROCESS mode.
"""
from __future__ import annotations

import json
import threading
import time

METRICS_KEY_PREFIX = "cipherpost:metrics"


class Counters:
    """Thread-safe local counter registry."""

    def __init__(self, worker: str):
        self.worker = worker
        self._values: dict[str, float] = {}
        self._lock = threading.Lock()

    def inc(self, name: str, by: float = 1):
        with self._lock:
            self._values[name] = self._values.get(name, 0.0) + by

    def set(self, name: str, value: float):
        with self._lock:
            self._values[name] = float(value)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._values)


class Gossiper:
    def __init__(self, r, worker: str, interval: float = 5.0, ttl: float = 30.0):
        self.r = r
        self.worker = worker
        self.interval = interval
        self.ttl = ttl
        self.counters = Counters(worker)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._t.start()

    def stop(self):
        self._stop.set()
        self._t.join(timeout=2)

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self._push()
            except Exception:
                pass

    def _push(self):
        snap = self.counters.snapshot()
        snap["ts"] = time.time()
        self.r.setex(f"{METRICS_KEY_PREFIX}:{self.worker}", int(self.ttl),
                     json.dumps(snap))

    def push_now(self):
        self._push()