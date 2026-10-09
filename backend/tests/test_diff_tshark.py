"""Task 3: unit + fixture tests for scripts/diff_tshark.py.

Covers the previously mismatching case (TLS 1.3 ServerHello cipher reported
as "tshark found no ciphers"): root causes were (1) reading pkt["layers"]
instead of pkt["_source"]["layers"], (2) wrong supported_version field name,
(3) whole-file set comparison instead of per-handshake pairs.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import shutil

import pytest

from scripts import diff_tshark as D


def test_layers_unwrap_and_hex():
    # Old code read pkt["layers"] (always empty); real path is _source.layers
    # with list values.
    pkt = {"_source": {"layers": {
        "tls.handshake.type": ["2"],
        "tls.handshake.ciphersuite": ["0x1301"],
        "tls.handshake.extensions.supported_version": ["0x0304"],
    }}}
    layers = D._layers(pkt)
    assert D._one(layers, "tls.handshake.type") == "2"
    assert D._hex_int("0x1301") == 0x1301
    assert D._hex_int("771") == 771
    assert D._hex_int(None) is None
    assert D._hex_int("bogus") is None
    assert D._cipher_name(0x1301) == "TLS_AES_128_GCM_SHA256"
    assert D._cipher_name(0x1302) == "TLS_AES_256_GCM_SHA384"
    assert D._cipher_name(0xFFFF) is None
    # old (broken) path yields nothing
    assert D._layers({"layers": {}}) == {}


def _u16(v):
    return v.to_bytes(2, "big")


def _ext(etype, body):
    return _u16(etype) + _u16(len(body)) + body


def _client_hello_record():
    ciphers = _u16(0x1301)
    sni_entry = b"\x00" + _u16(len(b"mail.test")) + b"mail.test"
    exts = (_ext(0, _u16(len(sni_entry)) + sni_entry)
            + _ext(43, bytes([2]) + _u16(0x0304)))
    body = (_u16(0x0303) + b"\x11" * 32 + bytes([0])
            + _u16(len(ciphers)) + ciphers + bytes([1, 0])
            + _u16(len(exts)) + exts)
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(hs).to_bytes(2, "big") + hs


def _server_hello_record():
    exts = _ext(43, _u16(0x0304))
    body = (_u16(0x0303) + b"\x22" * 32 + bytes([0]) + _u16(0x1301)
            + bytes([0]) + _u16(len(exts)) + exts)
    hs = bytes([2]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x03]) + len(hs).to_bytes(2, "big") + hs


def _write_synthetic_pcap(path):
    """SYNTHETIC minimal SMTP+TLS1.3 capture (hand-built bytes, one session)."""
    import dpkt
    from dpkt.ethernet import Ethernet
    from dpkt.ip import IP
    from dpkt.tcp import TCP
    import socket as _sock
    c_ip = _sock.inet_aton("10.9.0.1")
    s_ip = _sock.inet_aton("10.9.0.2")
    c_port, s_port = 40000, 587
    seq_c, seq_s = 1000, 5000
    pkts = []

    def tcp(src, sport, dst, dport, seq, ack, flags, data=b""):
        t = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags,
                data=data, win=65535)
        ip = IP(src=src, dst=dst, p=6, data=t)
        return Ethernet(dst=b"\x00" * 6, src=b"\x00" * 6, type=0x0800, data=ip)

    banner = b"220 mail.test ESMTP synthetic\r\n"
    pkts.append(tcp(c_ip, c_port, s_ip, s_port, seq_c, 0, dpkt.tcp.TH_SYN))
    seq_c += 1
    pkts.append(tcp(s_ip, s_port, c_ip, c_port, seq_s, seq_c, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))
    seq_s += 1
    pkts.append(tcp(c_ip, c_port, s_ip, s_port, seq_c, seq_s, dpkt.tcp.TH_ACK))
    pkts.append(tcp(s_ip, s_port, c_ip, c_port, seq_s, seq_c, dpkt.tcp.TH_ACK, banner))
    seq_s += len(banner)
    ch = _client_hello_record()
    pkts.append(tcp(c_ip, c_port, s_ip, s_port, seq_c, seq_s, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, ch))
    seq_c += len(ch)
    sh = _server_hello_record()
    pkts.append(tcp(s_ip, s_port, c_ip, c_port, seq_s, seq_c, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, sh))
    seq_s += len(sh)
    pkts.append(tcp(c_ip, c_port, s_ip, s_port, seq_c, seq_s, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK))
    pkts.append(tcp(s_ip, s_port, c_ip, c_port, seq_s, seq_c + 1, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK))
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, p in enumerate(pkts):
            w.writepkt(bytes(p), ts=i * 0.01)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="needs tshark")
def test_diff_agrees_on_synthetic_tls13(tmp_path):
    """Previously mismatching case end to end (synthetic fixture)."""
    pcap = tmp_path / "synthetic_tls13.pcap"
    _write_synthetic_pcap(str(pcap))
    res = D.diff_one(pcap)
    assert not res.get("skip"), res.get("skip")
    assert res["disagreements"] == [], res["disagreements"]
    ours = {tuple(sorted(d.items())) for d in res["ours"]}
    assert res["ours"], "expected one analyzed session"
    sa = res["ours"][0]
    assert sa["tls_version"] == 0x0304
    assert sa["cipher"] == "TLS_AES_256_GCM_SHA384"


@pytest.mark.skipif(shutil.which("tshark") is None, reason="needs tshark")
def test_diff_agrees_on_real_pq_capture():
    """Committed lab capture (Item 2) through the fixed script."""
    from pathlib import Path
    res = D.diff_one(Path("tests/real/pq_hybrid_lab_01.pcap"))
    assert not res.get("skip"), res.get("skip")
    assert res["disagreements"] == [], res["disagreements"]
