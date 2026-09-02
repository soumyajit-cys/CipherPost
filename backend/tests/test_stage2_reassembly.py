"""Stage 2 tests: reassembly + session classification against labeled corpus."""
import glob
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest

from app.parsing.reassembly import (
    StreamAssembler, reconstruct_sessions, Protocol, find_starttls_offset,
    _ip_str, IMPLICIT_TLS_PORTS,
)
from app.parsing.tls_records import parse_tls_records


def get_fixtures():
    d = Path("tests/fixtures")
    if not d.exists():
        pytest.skip("corpus not generated; run generate_corpus first")
    return sorted(glob.glob("tests/fixtures/*.pcap"))


@pytest.mark.parametrize("pcap_path", get_fixtures())
def test_every_fixture_yields_session(pcap_path):
    sessions = reconstruct_sessions(pcap_path)
    assert len(sessions) >= 1, f"{pcap_path} failed to produce a session"
    s = sessions[0]
    assert s.protocol.value in ("SMTP", "IMAP", "POP3")


def test_starttls_transition_offsets():
    smtp = reconstruct_sessions("tests/fixtures/smtp_tls12_starttls.pcap")[0]
    assert smtp.is_starttls and smtp.transition_offset is not None
    # EHLO+STARTTLS before handshake
    assert b"STARTTLS" in smtp.plaintext_segment
    assert smtp.tls_segment[:1] == b"\x16"  # handshake record

    imap = reconstruct_sessions("tests/fixtures/imap_tls10_weak.pcap")[0]
    assert imap.is_starttls and imap.transition_offset is not None

    pop3 = reconstruct_sessions("tests/fixtures/pop3_export_cipher.pcap")[0]
    assert pop3.is_starttls and pop3.transition_offset is not None


def test_implicit_tls_no_transition():
    s = reconstruct_sessions("tests/fixtures/imap_tls13_strong.pcap")[0]
    assert not s.is_starttls
    assert s.transition_offset == 0
    assert s.server_port in IMPLICIT_TLS_PORTS
    assert s.tls_segment[:1] == b"\x16"


def test_starttls_strip_detected():
    smtp = reconstruct_sessions("tests/fixtures/smtp_starttls_strip.pcap")[0]
    assert smtp.tls_segment == b""
    assert smtp.transition_offset is None
    assert not smtp.is_starttls
    assert b"MAIL FROM" in smtp.plaintext_segment


def test_protocol_fallback_by_banner():
    # Direct heuristic test: SMTP banner on non-standard port
    from app.parsing.reassembly import detect_protocol, Session
    sess = Session(protocol=Protocol.UNKNOWN, five_tuple="a:1->b:2",
                   client_ip="a", server_ip="b", client_port=9999, server_port=9999)
    proto = detect_protocol(sess, b"EHLO x\r\n", b"220 mail ESMTP Postfix\r\n")
    assert proto == Protocol.SMTP


def _shot(asm, src, dst, sport, dport, seq, ack, payload, flags, ts):
    asm.feed(src, dst, sport, dport, seq, ack, payload, flags, ts)


def test_reassembly_out_of_order_and_retransmit():
    asm = StreamAssembler()
    isn = 999
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, isn, 0, b"", 0x02, 0.5)   # SYN
    seq = isn + 1
    chunks = {0: b"HELLO WORLD ", 1: b"THIS IS ", 2: b"A MESSAGE"}
    # send segment 2 first, then segment 0, retransmit 0, then 1
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 14, 7000, chunks[2], 0x18, 1.0)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq, 7000, chunks[0], 0x18, 1.01)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq, 7000, chunks[0], 0x18, 1.02)  # retx
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 11, 7000, chunks[1], 0x18, 1.03)
    # server SYN-ACK + FIN to complete
    _shot(asm, "2.2.2.2", "1.1.1.1", 143, 5555, 6999, seq + 25, b"", 0x12, 1.5)
    _shot(asm, "2.2.2.2", "1.1.1.1", 143, 5555, 7000, seq + 25, b"", 0x11, 2.0)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 25, 7001, b"", 0x11, 2.01)
    streams = asm.emit()
    assert len(streams) == 1
    s = streams[0]
    assert s.plaintext_segment == b"HELLO WORLD THIS IS A MESSAGE"


def test_reassembly_gap_keeps_ordering():
    asm = StreamAssembler()
    isn = 999
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, isn, 0, b"", 0x02, 0.5)
    seq = isn + 1
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 11, 7000, b"cf", 0x18, 1.0)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq, 7000, b"ab", 0x18, 1.01)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 2, 7000, b"cd", 0x18, 1.02)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 4, 7000, b"e", 0x18, 1.03)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 13, 7000, b"g", 0x18, 1.04)
    _shot(asm, "2.2.2.2", "1.1.1.1", 143, 5555, 6999, seq + 14, b"", 0x12, 1.5)
    _shot(asm, "2.2.2.2", "1.1.1.1", 143, 5555, 7000, seq + 14, b"", 0x11, 2.0)
    _shot(asm, "1.1.1.1", "2.2.2.2", 5555, 143, seq + 14, 7001, b"", 0x11, 2.01)
    streams = asm.emit()
    assert len(streams) == 1
    assert streams[0].plaintext_segment == b"abcdefg"


def test_ground_truth_vs_classifier():
    with open("tests/fixtures/corpus_index.json") as f:
        idx = json.load(f)
    for ent in idx["files"]:
        pcap = f"tests/fixtures/{ent['name']}.pcap"
        sessions = reconstruct_sessions(pcap)
        assert sessions, f"{ent['name']} produced no sessions"
        s = sessions[0]
        # protocol matches ground truth
        assert s.protocol.value == ent["protocol"]
        # STARTTLS flags match
        if ent.get("use_starttls"):
            assert s.is_starttls, f"{ent['name']} should use STARTTLS"
        if ent.get("tls_version") is None:
            # stripped/plaintext sessions
            assert s.transition_offset is None
        elif ent.get("implicit_tls"):
            assert not s.is_starttls and s.transition_offset == 0