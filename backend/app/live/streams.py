"""
Redis Stream bus helpers: publish sessions/findings/alerts; xread-group
consumer; pub/sub fan-out for SSE.

Phase 2 reliability: at-least-once consumers (ACK after durable handling),
stuck-entry reclaim (XAUTOCLAIM), dead-letter streams, and a bounded
resilient publisher for the capture path (backoff+jitter, drop-oldest).
"""
from __future__ import annotations

import json
import random
import time
from collections import deque
from typing import Any

from app.core.config import settings
from app.live.serialize import session_to_payload


def _hgetall(r, key: str) -> dict:
    try:
        return {k.decode(): v.decode() for k, v in (r.hgetall(key) or {}).items()}
    except Exception:
        return {}


def dlq_name(stream: str) -> str:
    return f"{stream}{settings.STREAM_DLQ_SUFFIX}"


def note_attempt(r, stream: str, entry_id: str, ttl: int = 86400) -> int:
    """Increment delivery-attempt counter for (stream, entry). Returns attempts."""
    try:
        key = f"{stream}:attempts"
        n = r.hincrby(key, entry_id, 1)
        try:
            r.expire(key, ttl)
        except Exception:
            pass
        return int(n)
    except Exception:
        return 1


def clear_attempts(r, stream: str, entry_id: str) -> None:
    try:
        r.hdel(f"{stream}:attempts", entry_id)
    except Exception:
        pass


def publish(r, stream: str, payload: dict | bytes, maxlen: int = 5000) -> str | None:
    """XADD a JSON/bytes value onto a Redis stream. Returns entry id or None."""
    try:
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        return r.xadd(stream, {"v": payload}, maxlen=maxlen, approximate=True)
    except Exception as e:
        raise RuntimeError(f"publish to {stream} failed: {e}") from e


def publish_session(r, sess) -> str | None:
    return publish(r, settings.SESSION_STREAM, session_to_payload(sess))


def publish_finding(r, finding: dict) -> str | None:
    return publish(r, settings.FINDINGS_STREAM, finding)


def publish_alert(r, alert: dict) -> str | None:
    return publish(r, settings.ALERT_STREAM, alert)


def notify(r, channel: str, event_type: str, data: dict) -> None:
    """Pub/Sub fan-out for the SSE/dashboard layer."""
    try:
        r.publish(
            f"{settings.LIVE_PUBSUB_PREFIX}:{channel}",
            json.dumps({"event": event_type, "data": data, "ts": time.time()}),
        )
    except Exception:
        pass


def _decode_fields(fields: Any) -> Any | None:
    try:
        d = dict(fields)
        v = d.get("v", d.get(b"v"))
        if isinstance(v, bytes):
            return json.loads(v)
        return v
    except Exception:
        return None


class StreamConsumer:
    """XREADGROUP consumer with at-least-once semantics.

    - `poll_raw()` returns [(entry_id, payload)] WITHOUT acking.
    - `ack(eid)` acks after durable handling; `poll()` is the legacy
      at-most-once path (kept for dashboard/tests) and still acks on read.
    - `reclaim()` uses XAUTOCLAIM to reassign stuck entries to this consumer.
    - `dead_letter(eid, payload, error, attempts)` moves poison messages to DLQ.
    """

    def __init__(self, r, stream: str, group: str, consumer: str, batch: int = 8):
        self.r = r
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.batch = batch
        try:
            r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception:
            pass  # group already exists

    def poll_raw(self, timeout_ms: int = 750) -> list[tuple[str, Any]]:
        """Read without acking. Caller must ack() after durable handling."""
        try:
            resp = self.r.xreadgroup(
                self.group, self.consumer, {self.stream: ">"},
                count=self.batch, block=timeout_ms,
            )
        except Exception:
            return []
        out: list[tuple[str, Any]] = []
        if resp:
            for _, entries in resp:
                for eid, fields in entries:
                    eid_s = eid.decode() if isinstance(eid, bytes) else str(eid)
                    payload = _decode_fields(fields)
                    if payload is None:
                        continue
                    out.append((eid_s, payload))
        return out

    def poll(self, timeout_ms: int = 750) -> list[Any]:
        """Legacy at-most-once poll (acks on read). Prefer poll_raw + ack."""
        items = self.poll_raw(timeout_ms=timeout_ms)
        out = []
        for eid, payload in items:
            out.append(payload)
            try:
                self.r.xack(self.stream, self.group, eid)
            except Exception:
                pass
        return out

    def ack(self, entry_id: str) -> None:
        try:
            self.r.xack(self.stream, self.group, entry_id)
        except Exception:
            pass

    def reclaim(self, idle_ms: int | None = None, count: int | None = None) -> list[tuple[str, Any]]:
        """Reassign stuck entries (idle > threshold) to this consumer."""
        idle = idle_ms if idle_ms is not None else settings.STREAM_IDLE_RECLAIM_MS
        batch = count if count is not None else settings.STREAM_RECLAIM_BATCH
        try:
            # XAUTOCLAIM <key> <group> <consumer> <min-idle-time> <start> [COUNT n]
            claimed = self.r.xautoclaim(self.stream, self.group, self.consumer,
                                        idle, "0-0", count=batch)
        except Exception:
            return []
        out: list[tuple[str, Any]] = []
        try:
            entries = claimed[1] if isinstance(claimed, (list, tuple)) else []
        except Exception:
            entries = []
        for eid, fields in entries or []:
            eid_s = eid.decode() if isinstance(eid, bytes) else str(eid)
            payload = _decode_fields(fields)
            if payload is None:
                continue
            out.append((eid_s, payload))
        return out

    def dead_letter(self, entry_id: str, payload: Any, error: str, attempts: int) -> None:
        try:
            self.r.xadd(dlq_name(self.stream),
                        {"v": json.dumps({"entry_id": entry_id, "payload": payload,
                                          "error": str(error)[:500],
                                          "attempts": attempts,
                                          "ts": time.time()}).encode()},
                        maxlen=5000, approximate=True)
        except Exception:
            pass
        try:
            self.r.xack(self.stream, self.group, entry_id)
        except Exception:
            pass

    def dlq_depth(self) -> int:
        try:
            info = self.r.xinfo_stream(dlq_name(self.stream))
            if isinstance(info, dict):
                for k in (b"length", "length"):
                    if k in info:
                        return int(info[k])
            return int(getattr(info, "length", 0) or 0)
        except Exception:
            return 0

    def pending_count(self) -> int:
        try:
            info = self.r.xinfo_groups(self.stream)
            for g in info:
                name = g.get(b"name", g.get("name", b""))
                if isinstance(name, bytes):
                    name = name.decode()
                if name == self.group:
                    pending = g.get(b"pending", g.get("pending", 0))
                    return int(pending)
        except Exception:
            pass
        return 0

    def queue_depth(self) -> int:
        try:
            info = self.r.xinfo_stream(self.stream)
            if isinstance(info, dict):
                for k in (b"length", "length"):
                    if k in info:
                        return int(info[k])
            return 0
        except Exception:
            return 0

    def replier(self, broker_config=None):
        """Reclaim stuck entries; returns number reclaimed (legacy name kept)."""
        return len(self.reclaim())


class ResilientPublisher:
    """Bounded publisher for the capture path.

    - Never blocks the sniff loop: failed publishes are queued in a bounded
      deque; when full, the oldest entry is dropped and counted.
    - `flush()` retries with exponential backoff + jitter.
    - Drop reasons counted via the injected `counter(name, by)` callable so
      `/metrics` can expose `sessions_dropped_total{reason}`.
    """

    def __init__(self, r_factory, stream: str, max_buffer: int | None = None,
                 counter=None):
        self._r_factory = r_factory
        self.stream = stream
        self.max_buffer = max_buffer if max_buffer is not None else settings.CAPTURE_PUBLISH_BUFFER
        self.buf: deque[tuple[str, bytes]] = deque()
        self.dropped = 0
        self._counter = counter

    def _count(self, reason: str, by: int = 1) -> None:
        self.dropped += by if reason == "buffer-full" else 0
        try:
            if self._counter is not None:
                self._counter(f"sessions_dropped_total{{reason=\"{reason}\"}}", by)
        except Exception:
            pass

    def publish(self, payload: bytes | dict, maxlen: int = 5000) -> str | None:
        try:
            r = self._r_factory()
            return publish(r, self.stream, payload, maxlen=maxlen)
        except Exception:
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            if len(self.buf) >= self.max_buffer:
                self.buf.popleft()
                self._count("buffer-full")
            self.buf.append((self.stream, data))
            self._count("buffered")
            return None

    def flush(self) -> int:
        """Retry buffered entries with backoff+jitter. Returns sent count."""
        sent = 0
        retries = settings.CAPTURE_PUBLISH_RETRIES
        base = settings.CAPTURE_PUBLISH_BACKOFF_MS / 1000.0
        cap = settings.CAPTURE_PUBLISH_BACKOFF_MAX_MS / 1000.0
        while self.buf:
            stream, data = self.buf[0]
            ok = False
            delay = base
            for _ in range(max(1, retries)):
                try:
                    r = self._r_factory()
                    publish(r, stream, data)
                    ok = True
                    break
                except Exception:
                    time.sleep(min(cap, delay) + random.uniform(0, delay * 0.25))
                    delay = min(cap, delay * 2)
            if not ok:
                break
            self.buf.popleft()
            sent += 1
        return sent

    def depth(self) -> int:
        return len(self.buf)


def read_all(r, stream: str, count: int = 200) -> list[dict]:
    """Plain XRANGE read for dashboard replay of recent events."""
    try:
        resp = r.xrevrange(stream, count=count)
    except Exception:
        return []
    out = []
    for eid, fields in resp:
        try:
            out.append(json.loads(dict(fields)[b"v"]) if b"v" in dict(fields) else {})
        except Exception:
            continue
    return out
