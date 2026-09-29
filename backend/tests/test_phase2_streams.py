"""Phase 2 Task 1: reliable Redis pipeline (fakeredis, no real infra needed)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import fakeredis

from app.live import streams as bus


def _r():
    return fakeredis.FakeRedis(decode_responses=False)


def test_poll_raw_does_not_ack_crash_redelivers():
    """Kill consumer mid-message: entry stays pending, reclaim redelivers it."""
    r = _r()
    stream, group = "test:sessions", "test-analysis"
    bus.publish(r, stream, {"five_tuple": "1.2.3.4:1-5.6.7.8:25", "n": 1})
    c1 = bus.StreamConsumer(r, stream, group, "c1")
    items = c1.poll_raw(timeout_ms=100)
    assert len(items) == 1
    eid, payload = items[0]
    assert payload["n"] == 1
    # Crash: no ack. Entry must still be pending.
    assert c1.pending_count() == 1
    # A new consumer reclaims the stuck entry (idle=0 for test).
    c2 = bus.StreamConsumer(r, stream, group, "c2")
    reclaimed = c2.reclaim(idle_ms=0)
    assert len(reclaimed) == 1
    assert reclaimed[0][1] == payload
    c2.ack(reclaimed[0][0])
    assert c2.pending_count() == 0


def test_redelivery_is_idempotent_by_deterministic_id():
    """Same payload redelivered twice maps to one session id (no duplicates)."""
    import sys
    sys.path.insert(0, "backend")
    from app.live.analyze import deterministic_session_id
    p = {"five_tuple": "a:1-b:2", "start_ts": 10.0, "end_ts": 11.0,
         "client_ip": "a", "server_ip": "b", "client_port": 1, "server_port": 2}
    assert deterministic_session_id(p) == deterministic_session_id(dict(p))
    # Simulated store keyed by deterministic id: second delivery is a dup.
    store = {}
    for _ in range(2):
        sid = deterministic_session_id(p)
        if sid not in store:
            store[sid] = p
    assert len(store) == 1


def test_poison_message_lands_in_dlq_after_n_attempts():
    from app.core.config import settings
    r = _r()
    stream, group = "test:poison", "g"
    bus.publish(r, stream, {"bad": True})
    c = bus.StreamConsumer(r, stream, group, "c1")
    eid, payload = c.poll_raw(timeout_ms=100)[0]
    attempts = 0
    for _ in range(settings.STREAM_MAX_ATTEMPTS):
        attempts = bus.note_attempt(r, stream, eid)
    assert attempts == settings.STREAM_MAX_ATTEMPTS
    c.dead_letter(eid, payload, "boom", attempts)
    assert c.dlq_depth() == 1
    assert c.pending_count() == 0


def test_redis_outage_then_recovery_with_resilient_publisher():
    r = _r()
    calls = {"fail": True}

    def factory():
        if calls["fail"]:
            raise ConnectionError("redis down")
        return r

    pub = bus.ResilientPublisher(factory, "test:outage", max_buffer=8)
    assert pub.publish({"a": 1}) is None  # buffered, sniff loop not blocked
    assert pub.depth() == 1
    calls["fail"] = False  # recovery
    assert pub.flush() == 1
    assert pub.depth() == 0
    assert r.xlen("test:outage") == 1


def test_buffer_full_drops_oldest_and_counts():
    counts = {}

    def factory():
        raise ConnectionError("always down")

    pub = bus.ResilientPublisher(factory, "test:full", max_buffer=2,
                                 counter=lambda name, by=1: counts.__setitem__(
                                     name, counts.get(name, 0) + by))
    pub.publish({"n": 1})
    pub.publish({"n": 2})
    pub.publish({"n": 3})  # evicts oldest
    assert pub.depth() == 2
    assert counts.get('sessions_dropped_total{reason="buffer-full"}', 0) == 1
    assert pub.dropped == 1
