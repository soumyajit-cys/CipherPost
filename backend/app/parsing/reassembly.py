"""
Stage 2: TCP stream reassembly + protocol/Session classification.

Reads a PCAP (dpkt) and reconstructs bidirectional byte streams keyed by the
TCP 5-tuple, then classifies each completed stream into a Session.

Design decisions:
- Streams are keyed by a directionless 5-tuple (normalized by ip:port
  ordering). Client/server roles within the stream are assigned by: SYN
  sender first, else the ephemeral port, else first-talker.
- Reassembly handles retransmissions, out-of-order (buffered by seq gaps
  relative to the lowest unfilled offset), and FIN/RST closure.
- Only FIN|RST-completed streams are emitted.
- Everything is bounds-checked; malformed packets are skipped, never fatal.

API: reconstruct_sessions(pcap_path) -> list[Session]
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from enum import Enum

import dpkt
from dpkt.ip import IP as DpktIP
from dpkt.ethernet import Ethernet as DpktEther
import dpkt.arp

from app.parsing.tls_records import (
    parse_tls_records, find_starttls_offset, find_tls_offset, TlsParseError,
)


class Protocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


IMPLICIT_TLS_PORTS = {465, 993, 995}
PORT_TO_PROTO = {
    25: Protocol.SMTP,
    465: Protocol.SMTP,
    587: Protocol.SMTP,
    110: Protocol.POP3,
    995: Protocol.POP3,
    143: Protocol.IMAP,
    993: Protocol.IMAP,
}


def _ip_str(x) -> str:
    """dpkt.pcap ips may be int, bytes, or str across versions."""
    if isinstance(x, str):
        return x
    if isinstance(x, bytes):
        try:
            return socket.inet_ntoa(x)
        except (ValueError, OSError):
            return x.decode(errors="replace")
    if isinstance(x, int):
        return socket.inet_ntoa(x.to_bytes(4, "big"))
    return str(x)


@dataclass
class Session:
    protocol: Protocol
    five_tuple: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    is_starttls: bool = False
    transition_offset: int | None = None      # byte offset into client stream where TLS begins
    plaintext_segment: bytes = b""            # client->server pre-TLS bytes
    plaintext_server_segment: bytes = b""     # server->client pre-TLS bytes
    tls_segment: bytes = b""                  # client->server from transition onwards
    tls_server_segment: bytes = b""           # server->client from transition onwards
    start_ts: float = 0.0
    end_ts: float = 0.0
    port_based: bool = False

    @property
    def five_tuple_full(self) -> str:
        return f"{self.client_ip}:{self.client_port}->{self.server_ip}:{self.server_port}"

    @property
    def tls_records(self):
        if not self.tls_segment:
            return []
        return parse_tls_records(self.tls_segment)

    def __repr__(self):
        return (
            f"<Session {self.protocol.value} {self.five_tuple_full} "
            f"starttls={self.is_starttls} tls_bytes={len(self.tls_segment)}>"
        )


@dataclass
class _HalfStream:
    base_seq: int | None = None           # SYN ISN (if observed), or first data seq
    frontier: int | None = None           # next seq position expected for output
    pending: dict = field(default_factory=dict)   # seq -> data (at/after frontier)
    buf: bytearray = field(default_factory=bytearray)  # emitted ordered bytes
    fin_seq: int | None = None
    rst: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_seq: int | None = None
    syn_ts: float = 0.0
    first_non_syn_ts: float = 0.0


@dataclass
class _Stream:
    """Bidirectional stream keyed by directionless 5-tuple."""
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    ha: _HalfStream = field(default_factory=_HalfStream)   # bytes A->B
    hb: _HalfStream = field(default_factory=_HalfStream)   # bytes B->A
    a_is_client: bool | None = None
    syn_by_a: bool = False
    syn_by_b: bool = False
    complete: bool = False
    first_ts: float = 0.0

    @classmethod
    def _store(cls, hs: _HalfStream, seq: int, data: bytes, ts: float) -> None:
        """Online TCP reassembly anchored at SYN ISN (base_seq = ISN+1)."""
        if not data:
            return
        if not hs.first_ts:
            hs.first_ts = ts
        hs.last_ts = ts
        if hs.syn_seq is not None and hs.base_seq is None:
            hs.base_seq = hs.syn_seq + 1
        if hs.base_seq is None:
            hs.base_seq = seq
        if hs.frontier is None:
            hs.frontier = hs.base_seq
        end = seq + len(data)
        # Fully-below-frontier: retransmit of already-emitted region
        if end <= hs.frontier:
            return
        # Partial overlap of the emitted region: keep only the tail
        if seq < hs.frontier:
            skip = hs.frontier - seq
            data = data[skip:]
            seq = hs.frontier
        # Now seq >= frontier: buffer and merge contiguous runs
        hs.pending[seq] = data
        cls._flush(hs)

    @staticmethod
    def _flush(hs: _HalfStream) -> None:
        while True:
            seg = hs.pending.get(hs.frontier)
            if seg is None:
                break
            hs.buf += seg
            hs.frontier += len(seg)
            del hs.pending[hs.frontier - len(seg)]

    def store(self, dir_a: bool, seq: int, data: bytes, ts: float) -> None:
        hs = self.ha if dir_a else self.hb
        self._store(hs, seq, data, ts)


class StreamAssembler:
    def __init__(self, idle_timeout: float = 900.0):
        self._streams: dict[tuple, _Stream] = {}
        self.idle_timeout = idle_timeout

    @staticmethod
    def _key(ip1, p1, ip2, p2) -> tuple:
        if (ip1, p1) <= (ip2, p2):
            return (ip1, p1, ip2, p2)
        return (ip2, p2, ip1, p1)

    def feed(self, src, dst, sport, dport, seq, ack, payload, flags, ts) -> None:
        ip_a, p_a, ip_b, p_b = self._key(src, sport, dst, dport)
        key = (ip_a, p_a, ip_b, p_b)
        st = self._streams.get(key)
        if st is None:
            st = _Stream(ip_a, p_a, ip_b, p_b, first_ts=ts)
            self._streams[key] = st
        src_ip = _ip_str(src)
        # is this packet in direction A->B?
        dir_a = (src_ip, sport) == (ip_a, p_a)
        syn = bool(flags & 0x02)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        hs = st.ha if dir_a else st.hb
        if syn:
            if dir_a:
                st.syn_by_a = True
            else:
                st.syn_by_b = True
            hs.syn_seq = seq
            hs.syn_ts = ts
        if fin:
            hs.fin_seq = seq + len(payload)
        if rst:
            hs.rst = True
        if payload:
            st.store(dir_a, seq, payload, ts)
        # Completion: RST either direction, or FIN in both directions
        if st.ha.rst or st.hb.rst or (st.ha.fin_seq is not None and st.hb.fin_seq is not None):
            st.complete = True

    def _resolve_client(self, st: _Stream) -> tuple[str, int] | None:
        """SYN sender is the client; else ephemeral port; else A side."""
        if st.syn_by_a and not st.syn_by_b:
            return (st.ip_a, st.port_a)
        if st.syn_by_b and not st.syn_by_a:
            return (st.ip_b, st.port_b)
        if st.port_a in PORT_TO_PROTO and st.port_b not in PORT_TO_PROTO:
            return (st.ip_b, st.port_b)
        if st.port_b in PORT_TO_PROTO and st.port_a not in PORT_TO_PROTO:
            return (st.ip_a, st.port_a)
        # first talker
        ta = st.ha.first_ts
        tb = st.hb.first_ts
        if ta and (not tb or ta < tb):
            return (st.ip_a, st.port_a)
        if tb and (not ta or tb < ta):
            return (st.ip_b, st.port_b)
        return (st.ip_a, st.port_a)

    def emit(self) -> list[Session]:
        out = []
        for key, st in self._streams.items():
            if not st.complete:
                continue
            c = self._resolve_client(st)
            if c == (st.ip_a, st.port_a):
                c_ip, c_port, s_ip, s_port = st.ip_a, st.port_a, st.ip_b, st.port_b
                client_bytes = bytes(st.ha.buf)
                server_bytes = bytes(st.hb.buf)
            else:
                c_ip, c_port, s_ip, s_port = st.ip_b, st.port_b, st.ip_a, st.port_a
                client_bytes = bytes(st.hb.buf)
                server_bytes = bytes(st.ha.buf)

            sess = Session(
                protocol=Protocol.UNKNOWN,
                five_tuple=f"{c_ip}:{c_port}->{s_ip}:{s_port}",
                client_ip=c_ip, server_ip=s_ip,
                client_port=c_port, server_port=s_port,
                start_ts=st.first_ts,
            )
            sess.protocol = detect_protocol(sess, client_bytes, server_bytes)
            if sess.protocol == Protocol.UNKNOWN:
                continue
            _assign_tls_segments(sess, client_bytes, server_bytes)
            out.append(sess)
        return out


PROTOCOL_BANNER_MARKERS = {
    b"ESMTP": Protocol.SMTP,
    b"Dovecot": Protocol.IMAP,
    b"IMAP4": Protocol.IMAP,
    b"+OK": Protocol.POP3,
}


def detect_protocol(session: Session, client_stream: bytes, server_stream: bytes) -> Protocol:
    """Ordered inference: ports first, then plaintext banner/command heuristics."""
    if session.server_port in PORT_TO_PROTO:
        session.port_based = True
        return PORT_TO_PROTO[session.server_port]
    probe = (server_stream[:4096] + b"\x00" + client_stream[:4096]).upper()
    for marker, proto in PROTOCOL_BANNER_MARKERS.items():
        if marker in probe:
            return proto
    uc = client_stream[:4096].upper()
    for cmd, proto in ((b"EHLO", Protocol.SMTP), (b"MAIL FROM", Protocol.SMTP),
                       (b"LOGIN", Protocol.IMAP), (b"a001", Protocol.IMAP),
                       (b"USER", Protocol.POP3), (b"PASS", Protocol.POP3)):
        if cmd in uc:
            return proto
    return Protocol.UNKNOWN


def _assign_tls_segments(sess: Session, client_bytes: bytes, server_bytes: bytes) -> None:
    implicit = sess.server_port in IMPLICIT_TLS_PORTS
    offset = None
    if not implicit:
        off = find_starttls_offset(client_bytes, sess.protocol.value)
        if off is not None and off < len(client_bytes):
            offset = off
            sess.is_starttls = True
    if implicit:
        offset = 0
        sess.is_starttls = False
    if offset is None:
        # Maybe TLS anyway (unexpected server, transformed stream)
        recs = []
        try:
            recs = parse_tls_records(client_bytes)
        except (TlsParseError, Exception):
            recs = []
        if recs:
            first = recs[0]
            header = bytes([first.content_type, first.version >> 8 & 0xFF, first.version & 0xFF])
            offset = client_bytes.find(header)
            offset = offset if offset != -1 else 0
            sess.is_starttls = False
    if offset is not None:
        sess.transition_offset = offset
        sess.plaintext_segment = client_bytes[:offset]
        sess.plaintext_server_segment = server_bytes if sess.is_starttls else b""
        sess.tls_segment = client_bytes[offset:]
        sess.tls_server_segment = server_bytes if sess.is_starttls else server_bytes
    else:
        sess.plaintext_segment = client_bytes
        sess.plaintext_server_segment = server_bytes
        sess.tls_segment = b""
        sess.tls_server_segment = b""


def read_pcap_streams(pcap_path: str) -> StreamAssembler:
    asm = StreamAssembler()
    with open(pcap_path, "rb") as f:
        try:
            cap = dpkt.pcap.Reader(f)
        except Exception as e:
            raise ValueError(f"invalid pcap: {e}") from e
        for ts, buf in cap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, DpktIP):
                    continue
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                tcp = ip.data
                payload = bytes(tcp.data)
                asm.feed(
                    src=_ip_str(ip.src), dst=_ip_str(ip.dst),
                    sport=tcp.sport, dport=tcp.dport,
                    seq=tcp.seq, ack=tcp.ack,
                    payload=payload, flags=tcp.flags, ts=ts,
                )
            except Exception:
                continue
    return asm


def reconstruct_sessions(pcap_path: str) -> list[Session]:
    asm = read_pcap_streams(pcap_path)
    return asm.emit()


def format_five_tuple(ip1, p1, ip2, p2) -> str:
    if (ip1, p1) <= (ip2, p2):
        return f"{ip1}:{p1}->{ip2}:{p2}"
    return f"{ip2}:{p2}->{ip1}:{p1}"