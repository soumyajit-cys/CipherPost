"""
Track 3: multi-agent heartbeats + consumer-group scaling proof.

Uses an in-memory fake implementing the Redis stream commands
StreamConsumer touches (xadd/xgroup_create/xreadgroup/xack/keys/get/setex),
so no Redis server is needed.
"""
import sys
import os
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))


class FakeRedis:
    """Minimal in-memory Redis streams + kv for StreamConsumer/AgentHeartbeat."""

    def __init__(self):
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.groups: dict[str, dict[str, dict]] = {}  # stream -> group -> {last, pending}
        self.kv: dict[str, tuple[str, float | None]] = {}
        self._seq = 0

    # -- kv --
    def setex(self, k, ttl, v):
        self.kv[k] = (v if isinstance(v, str) else v.decode(), time.time() + ttl)

    def get(self, k):
        hit = self.kv.get(k)
        if not hit:
            return None
        v, exp = hit
        if exp and time.time() > exp:
            del self.kv[k]
            return None
        return v

    def delete(self, k):
        self.kv.pop(k, None)

    def keys(self, pattern):
        import fnmatch
        return [k for k, (v, exp) in self.kv.items()
                if fnmatch.fnmatch(k, pattern) and (not exp or time.time() <= exp)]

    # -- streams --
    def xadd(self, stream, fields, maxlen=None, approximate=None):
        self._seq += 1
        eid = f"1-{self._seq}"
        self.streams.setdefault(stream, []).append((eid, dict(fields)))
        return eid

    def xgroup_create(self, stream, group, id="0", mkstream=False):
        self.streams.setdefault(stream, [])
        self.groups.setdefault(stream, {})[group] = {"cursor": 0, "pending": set()}

    def xreadgroup(self, group, consumer, streams, count=8, block=0):
        out = []
        for stream, _ in streams.items():
            entries = self.streams.get(stream, [])
            g = self.groups[stream][group]
            batch = []
            while len(batch) < count and g["cursor"] < len(entries):
                eid, fields = entries[g["cursor"]]
                g["cursor"] += 1
                g["pending"].add(eid)
                batch.append((eid, fields))
            if batch:
                out.append((stream.encode(), batch))
        return out

    def xack(self, stream, group, eid):
        self.groups[stream][group]["pending"].discard(eid)
        return 1


def test_two_analyzers_share_one_group_without_duplicates():
    from app.live.streams import StreamConsumer, publish
    r = FakeRedis()
    for i in range(10):
        publish(r, "cipherpost:sessions", {"protocol": "SMTP", "i": i})
    c1 = StreamConsumer(r, "cipherpost:sessions", "analysis-workers", "a1", batch=10)
    c2 = StreamConsumer(r, "cipherpost:sessions", "analysis-workers", "a2", batch=10)
    got1 = c1.poll(timeout_ms=10)
    got2 = c2.poll(timeout_ms=10)
    # group semantics: every message delivered exactly once across consumers
    assert len(got1) + len(got2) == 10
    assert len(got1) == 10 and got2 == []  # c1 drained first; c2 gets nothing new
    # separate group (alerts) gets its own full copy
    c3 = StreamConsumer(r, "cipherpost:sessions", "alert-workers", "x1", batch=10)
    got3 = c3.poll(timeout_ms=10)
    assert len(got3) == 10


def test_agent_heartbeat_roundtrip():
    from app.live.agents import AgentHeartbeat, list_agents, default_agent_id
    r = FakeRedis()
    hb = AgentHeartbeat(r, "site-a/eth0", interval=60, ttl=60)
    hb.start({"mode": "live", "iface": "eth0"}, lambda: {"packets_seen": 42})
    agents = list_agents(r)
    assert len(agents) == 1
    assert agents[0]["agent_id"] == "site-a/eth0"
    assert agents[0]["online"] is True
    assert agents[0]["stats"]["packets_seen"] == 42
    hb.stop()
    assert list_agents(r) == []
    assert default_agent_id("eth0").endswith("/eth0")
