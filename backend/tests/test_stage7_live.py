"""
Stage 6/7: live pipeline regression tests (replay harness + live components).

These tests use the direct replay path (no network, no redis required) to
validate that the streaming reassembler agrees with the batch reassembler,
that malformed packets never crash the live path, and that alert dedup works.
"""
import tempfile
from pathlib import Path

def test_live_reassembler_matches_batch():
    """Streaming reassembler should find same number of email sessions as batch."""
    from app.parsing.reassembly import reconstruct_sessions
    from app.live.packets import iter_pcap_packets
    from app.live.reassembly import LiveReassembler
    import time
    for name in ["smtp_tls13_strong.pcap", "imap_selfsigned.pcap", "smtp_starttls_strip.pcap"]:
        p = f"tests/fixtures/{name}"
        batch = reconstruct_sessions(p)
        asm = LiveReassembler(idle_timeout=2, max_sessions=100, max_buffer_bytes=2*1024*1024)
        for pkt in iter_pcap_packets(p):
            asm.feed_packet(pkt)
        live = asm.tick(time.time()+9999)
        live += asm.drain()
        assert len(live) == len(batch), f"{name}: live {len(live)} != batch {len(batch)}"
        # at least one protocol detected
        for s in live:
            assert s.protocol.value in ("SMTP","IMAP","POP3")

def test_live_replay_harness_direct():
    from scripts.replay_harness import replay_direct
    sess, analyses, scores = replay_direct("tests/fixtures/imap_tls13_strong.pcap")
    assert len(sess) == 1
    assert analyses[0].protocol in ("IMAP","SMTP","POP3")

def test_rolling_store_write_and_purge():
    from app.live.retention import RollingRawStore
    with tempfile.TemporaryDirectory() as d:
        store = RollingRawStore(d, retention_seconds=1, segment_seconds=1)
        ref = store.write(1000.0, b"hello frame")
        assert ref is not None
        frames = store.read_frames([ref])
        assert len(frames) == 1
        # purge after window
        import time
        removed = store.purge(now=1000+10)
        assert removed >= 1

def test_alert_dedup_and_rate_limit():
    from app.live.alerts import AlertDispatcher
    class FakeRedis:
        def __init__(self): self.store={}
        def xgroup_create(self, *a, **k): pass
        def xinfo_groups(self, *a, **k): return []
        def xinfo_stream(self, *a, **k): return {}
        def setex(self, *a, **k): pass
        def get(self, *a, **k): return None
        def keys(self, *a, **k): return []
        def hgetall(self, *a, **k): return {}
        def xadd(self, *a, **k): return "0-1"
        def xreadgroup(self, *a, **k): return []
        def xack(self, *a, **k): return 1
        def publish(self, *a, **k): return 1
    r = FakeRedis()
    disp = AlertDispatcher(redis_client=r, adapters=[])
    disp.min_sev = 0  # alert everything
    f = {"max_severity":"high","five_tuple":"1.1.1.1:123->2.2.2.2:25","rule_id":"test-rule","severity":"high"}
    assert disp._should_alert(f) is True
    disp._dedup["test-rule:1.1.1.1:123->2.2.2.2:25"] = __import__("time").time()
    assert disp._should_alert(f) is False  # deduped

def test_fuzz_live_packets_no_crash():
    from app.live.packets import Packet
    from app.live.reassembly import LiveReassembler
    asm = LiveReassembler()
    # garbage payloads, zero ports, huge seq jumps, etc.
    cases = [
        Packet(0, "0.0.0.0","0.0.0.0", 0,0, 0,0, 0, b"\xff"*1000),
        Packet(1, "10.0.0.1","10.0.0.2", 25, 99999, 2**31-1, 0, 0x02, b""),
        Packet(2, "a","b", 25,25, 0,0, 0xFF, b"\x00"*5000),
        Packet(3, "1.1.1.1","2.2.2.2", 143, 143, 100, 200, 0x18, b"STARTTLS\r\n"),
    ]
    for p in cases:
        asm.feed_packet(p)
    # drain should not crash
    import time
    asm.tick(time.time()+100)

def test_serialization_roundtrip():
    from app.live.serialize import session_to_payload, session_from_payload
    from app.parsing.reassembly import Session, Protocol
    s = Session(protocol=Protocol.SMTP, five_tuple="a:1->b:25", client_ip="a", server_ip="b", client_port=1, server_port=25,
                is_starttls=True, transition_offset=10, plaintext_segment=b"hello", tls_segment=b"\x16\x03\x01", start_ts=1, end_ts=2)
    s.closed_by = "fin"
    s.raw_refs = [("cap-1.seg", 0, 100)]
    raw = session_to_payload(s)
    s2 = session_from_payload(raw)
    assert s2.five_tuple == s.five_tuple
    assert s2.plaintext_segment == s.plaintext_segment
    assert s2.raw_refs == [("cap-1.seg", 0, 100)]
