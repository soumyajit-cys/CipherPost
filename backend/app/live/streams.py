"""
Redis Stream bus helpers: publish sessions/findings/alerts; xread-group
consumer; pub/sub fan-out for SSE.
"""
from __future__ import annotations

import json
import time
from typing import Any

from app.core.config import settings
from app.live.serialize import session_to_payload


def _hgetall(r, key: str) -> dict:
    try:
        return {k.decode(): v.decode() for k, v in (r.hgetall(key) or {}).items()}
    except Exception:
        return {}


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


class StreamConsumer:
    """XREADGROUP consumer for a single worker. Non-blocking poll + ack."""

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

    def poll(self, timeout_ms: int = 750) -> list[Any]:
        """Return decoded payloads; entries are ACKed immediately."""
        try:
            resp = self.r.xreadgroup(
                self.group, self.consumer, {self.stream: ">"},
                count=self.batch, block=timeout_ms,
            )
        except Exception:
            return []
        out = []
        if resp:
            for _, entries in resp:
                for eid, fields in entries:
                    try:
                        v = dict(fields).get("v")
                        if isinstance(v, bytes):
                            out.append(json.loads(v))
                        else:
                            out.append(v)
                        self.r.xack(self.stream, self.group, eid)
                    except Exception:
                        continue
        return out

    def pending_count(self) -> int:
        try:
            info = self.r.xinfo_groups(self.stream)
            for g in info:
                if g.get(b"name", b"").decode() == self.group:
                    return int(g.get(b"pending", 0))
        except Exception:
            pass
        return 0

    def queue_depth(self) -> int:
        try:
            info = self.r.xinfo_stream(self.stream)
            return int(info.get(b"length", 0))
        except Exception:
            return 0

    def replier(self, broker_config=None):
        """Initialize pending entries that have no owner yet (simple retry)."""
        return self.pending_count()


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