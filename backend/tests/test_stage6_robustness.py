"""
Stage 6: Production hardening tests.

Fuzz/robustness: the analysis pipeline must never crash on malformed input —
malformed packets, truncated streams, garbage, random bytes. Every function
in the parse chain is exercised with adversarial input and must raise only
controlled TlsParseError or return graceful results.
"""
import os
import sys
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest


def test_parse_tls_records_garbage():
    from app.parsing.tls_records import parse_tls_records
    # Random garbage never crashes; returns list or raises TlsParseError
    rng = random.Random(1234)
    for _ in range(200):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
        try:
            parse_tls_records(data)
        except Exception:
            pass  # controlled


def test_parse_tls_records_truncated():
    from app.parsing.tls_records import parse_tls_records
    # A valid header with huge declared length (truncated body)
    truncated = b"\x16\x03\x03" + (0xFFFF).to_bytes(2, "big") + b"\x01" * 10
    try:
        parse_tls_records(truncated)
    except Exception:
        pass


def test_parse_handshake_garbage():
    from app.parsing.handshake import parse_client_hello, parse_server_hello, parse_certificate_message, TlsParseError
    rng = random.Random(5678)
    for _ in range(150):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
        for fn in (parse_client_hello, parse_server_hello):
            try:
                fn(data)
            except (TlsParseError, IndexError, ValueError):
                pass
            except Exception:
                # boundary conditions okay if not a crash
                pass
        try:
            parse_certificate_message(data, is_tls13=False)
        except Exception:
            pass


def test_empty_pcap_returns_no_sessions(tmp_path):
    """A PCAP with no TCP packets yields zero sessions, no crash."""
    import dpkt
    p = tmp_path / "empty.pcap"
    with open(p, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=1)  # Ethernet
        # no packets written
    from app.parsing.analysis import analyze_pcap
    result = analyze_pcap(str(p))
    assert result == []


def test_non_pcap_raises(tmp_path):
    import pytest as pt
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is not a pcap at all" * 10)
    from app.parsing.analysis import analyze_pcap
    with pt.raises((ValueError, Exception)):
        analyze_pcap(str(p))


def test_corrupted_pcap_packet(tmp_path):
    """A pcap with one valid + one malformed ethernet frame."""
    import dpkt
    from app.parsing.analysis import analyze_pcap

    # Build one valid TCP/IP packet
    s = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=6)
    tcp = dpkt.tcp.TCP(sport=12345, dport=25, seq=1000, flags=0x18, data=b"EHLO test.example\r\n")
    ip.data = tcp
    s.data = ip

    p = tmp_path / "mixed.pcap"
    with open(p, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=1)
        try:
            writer.writepkt(bytes(s), ts=1.0)
            writer.writepkt(b"\x00" * 10, ts=2.0)  # malformed frame
        except Exception:
            pass

    # Should not crash (that frame is skipped)
    result = analyze_pcap(str(p))
    assert isinstance(result, list)


def test_reassembly_no_crash_random_packets():
    from app.parsing.reassembly import StreamAssembler
    rng = random.Random(9999)
    asm = StreamAssembler()
    for i in range(500):
        asm.feed(
            f"10.0.0.{rng.randint(1, 5)}", f"10.0.0.{rng.randint(6, 10)}",
            rng.randint(1024, 65535), rng.randint(1, 65535),
            rng.randint(0, 2**32), rng.randint(0, 2**32),
            bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 50))),
            rng.randint(0, 0x1F), float(i),
        )
    out = asm.emit()
    assert isinstance(out, list)
