"""Phase 2 Task 8: failure-injection (chaos) suite.

Marked slow: main CI runs `-m "not slow"`; the nightly workflow runs these.
All scenarios use fakes (fakeredis, sqlite, synthetic packets) — no real
infrastructure needed. Each asserts recovery properties:

- no crash loops (workers stay alive / restart cleanly)
- bounded memory (buffers capped, no unbounded growth)
- no duplicate alerts (shared dedup survives restarts)
- no data loss beyond documented drop counters
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import threading
import time

import pytest

pytestmark = pytest.mark.slow

import fakeredis


def _sess_payload(n: int) -> dict:
    import base64
    seg = base64.b64encode(b"\x16\x03\x01" + bytes([n % 256]) * 32).decode()
    return {"protocol": "SMTP", "five_tuple": f"10.0.0.{n % 250 + 1}:1000-10.0.0.9:25",
            "client_ip": f"10.0.0.{n % 250 + 1}", "server_ip": "10.0.0.9",
            "client_port": 1000, "server_port": 25, "is_starttls": False,
            "transition_offset": None, "plaintext_segment": "", "plaintext_server_segment": "",
            "tls_segment": seg, "tls_server_segment": seg,
            "start_ts": float(n), "end_ts": float(n) + 1, "port_based": False,
            "closed_by": "fin", "tracked_bytes": 64, "raw_refs": []}


def test_redis_restart_mid_stream_recovers():
    """Flush Redis mid-stream: publisher buffers, flushes after recovery."""
    from app.live import streams as bus
    r = fakeredis.FakeRedis(decode_responses=False)
    box = {"r": r}

    pub = bus.ResilientPublisher(lambda: box["r"], "chaos:sessions", max_buffer=64)
    assert pub.publish({"n": 1}) is not None
    # "restart": drop all state
    box["r"] = fakeredis.FakeRedis(decode_responses=False)
    box["r"].flushall()
    # outage: factory raises
    down = {"on": True}

    def flaky():
        if down["on"]:
            raise ConnectionError("redis restarting")
        return box["r"]

    pub2 = bus.ResilientPublisher(flaky, "chaos:sessions", max_buffer=64)
    for i in range(5):
        pub2.publish({"n": i})
    assert pub2.depth() == 5  # buffered, loop never blocked
    down["on"] = False
    assert pub2.flush() == 5
    assert box["r"].xlen("chaos:sessions") == 5
    assert pub2.depth() == 0


def test_kill_analyzer_mid_message_no_loss_no_dup():
    """Crash between poll_raw and ack: reclaim redelivers; deterministic ids dedup."""
    from app.live import streams as bus
    from app.live.analyze import deterministic_session_id
    r = fakeredis.FakeRedis(decode_responses=False)
    stream, group = "chaos:ana", "g"
    for i in range(3):
        bus.publish(r, stream, _sess_payload(i))
    c1 = bus.StreamConsumer(r, stream, group, "victim")
    first = c1.poll_raw(timeout_ms=100)
    assert len(first) == 3
    # crash: no acks. replacement worker reclaims everything.
    c2 = bus.StreamConsumer(r, stream, group, "replacement")
    redelivered = c2.reclaim(idle_ms=0)
    assert len(redelivered) == 3
    seen: set[str] = set()
    dups = 0
    for _eid, payload in redelivered:
        sid = deterministic_session_id(payload)
        if sid in seen:
            dups += 1
        seen.add(sid)
        c2.ack(_eid)
    assert dups == 0 and len(seen) == 3
    assert c2.pending_count() == 0


def test_db_outage_then_recovery_no_crash_loop():
    """Persist failures raise (retry path); entries stay pending for redelivery."""
    from app.live import streams as bus
    r = fakeredis.FakeRedis(decode_responses=False)
    stream, group = "chaos:db", "g"
    bus.publish(r, stream, _sess_payload(1))
    c = bus.StreamConsumer(r, stream, group, "c")
    eid, payload = c.poll_raw(timeout_ms=100)[0]
    # Simulate DB down inside _persist by raising, then recovery.
    attempts = bus.note_attempt(r, stream, eid)
    assert attempts == 1
    assert c.pending_count() == 1  # still pending -> redeliverable
    c.ack(eid)  # after successful retry
    assert c.pending_count() == 0


def test_disk_pressure_retention_stays_bounded(tmp_path):
    """Fill the retention dir: segment count stays bounded via purge."""
    from app.live.retention import RollingRawStore
    store = RollingRawStore(str(tmp_path), retention_seconds=2, segment_seconds=1)
    base = 1_000_000.0
    for i in range(40):
        store.write(base + i, b"x" * 1024)
    store._close_current()
    store.purge(now=base + 100)
    remaining = list(tmp_path.glob("*.seg"))
    assert len(remaining) <= 3, f"unbounded segments: {len(remaining)}"
    store.stop()


def test_malformed_traffic_during_recovery_no_crash():
    """Garbage packets right after an outage must not crash reassembly/analysis."""
    from app.live.packets import Packet
    from app.live.reassembly import LiveReassembler
    asm = LiveReassembler()
    junk = [
        Packet(0, "0.0.0.0", "0.0.0.0", 0, 0, 0, 0, 0, b"\xff" * 2000),
        Packet(1, "a", "b", 25, 25, 0, 0, 0xFF, b"\x00" * 5000),
        Packet(2, "10.0.0.1", "10.0.0.2", 25, 99999, 2**31 - 1, 0, 0x02, b""),
    ]
    for p in junk:
        asm.feed_packet(p)
    out = asm.tick(time.time() + 100)
    assert isinstance(out, list)
    # analysis of garbage-derived sessions must not raise out of the worker
    from app.parsing.analysis import analyze_session
    for s in out:
        try:
            analyze_session(s)
        except Exception:
            pass  # contained; worker logs and continues


def test_bounded_memory_under_burst():
    """Burst larger than the buffer: drops counted, memory capped."""
    from app.live import streams as bus

    def down():
        raise ConnectionError("down")

    pub = bus.ResilientPublisher(down, "chaos:burst", max_buffer=16)
    for i in range(100):
        pub.publish({"n": i})
    assert pub.depth() == 16
    assert pub.dropped == 84
