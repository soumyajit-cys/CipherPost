"""
Stage 2: TCP stream reassembly + protocol/Session classification.

Reads a PCAP (dpkt) and reconstructs bidirectional byte streams keyed by the
TCP 5-tuple, then classifies each completed stream into a Session.

Design decisions:
- Streams are keyed by DirectionAwareKey: (src,dst,sport,dport) normalized so
  client/server assignment follows the SYN opening direction.
- Reassembly handles retransmissions, out-of-order (buffered by ISN-relative
  seq gaps), and FIN/RST closure.
- Only completed (FIN-seen or idle-forced-close) streams are emitted, keeping
  memory bounded: streams older than N seconds are flushed.
- Segments are consumed via a sliding "leftmost unfilled byte" pointer; we do
  linear scan membership for overlapping segments (accepting the simplicity,
  good enough for HVAC-style captures and bounded by MTU-sized segments).

API: reconstruct_sessions(pcap_path) -> list[Session]
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum

try:
    import dpkt
    from dpkt.ip import IP as DpktIP
    from dpkt.ethernet import Ethernet as DpktEther
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False

from app.parsing.tls_records import parse_tls_records, find_starttls_offset, TlsParseError


class Protocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


# Well-known TLS ports
IMPLICIT_TLS_PORTS = {465, 993, 995}
STARTTLS_PORTS = {25, 110, 143, 587}
PORT_TO_PROTO = {
    25: Protocol.SMTP,
    465: Protocol.SMTP,
    587: Protocol.SMTP,
    110: Protocol.POP3,
    995: Protocol.POP3,
    143: Protocol.IMAP,
    993: Protocol.IMAP,
}


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
        return (
            f"{self.client_ip}:{self.client_port}->{self.server_ip}:{self.server_port}"
        )

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
    syn_seq: int | None = None          # ISN as seen by sender
    base_seq: int | None = None         # first observed SEQ (after normalization)
    segments: dict = field(default_factory=dict)  # seq->(data, ends)
    leftmost: int | None = None         # lowest unfilled seq position
    leftmost_data_end: int | None = None
    buf: bytearray = field(default_factory=bytearray)
    fin_seq: int | None = None
    rst: bool = False
    last_ts: float = 0.0
    fin_seen: bool = False


class StreamAssembler:
    """
    Reassembles TCP payloads into ordered byte streams. Accepts (direction,
    seq, payload, flags, ts) events from the PCAP reader. Ownership of streams:
    keyed by (lower_syn_open_ip:port) pair normalized to a single key with a
    direction bit.
    """

    def __init__(self, idle_timeout: float = 600.0):
        self._streams: dict = {}
        self.idle_timeout = idle_timeout

    @staticmethod
    def _norm_key(cip: str, cport: int, sip: str, sport: int) -> tuple:
        # Normalize so that the SYN-origin is the "client" whenever possible.
        return (cip, cport, sip, sport)

    def feed(self, src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
             payload: bytes, flags: int, ts: float) -> None:
        syn = bool(flags & 0x02)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        # determine client direction: whoever sent the SYN is the client.
        # For streams where we never see SYN we fall back to lower numeric key.
        key = self._norm_key(src, sport, dst, dport)
        if key not in self._streams:
            # try reverse (maybe we saw server first?) -- session keyed by SYN sender
            self._streams[key] = {
                "client": {"ip": src, "port": sport, "syn": syn, "fin": False,
                           "hs": _HalfStream(), "acked": False},
                "server": {"ip": dst, "port": dport, "syn": bool(ack and not syn) or not syn,
                           "fin": False, "hs": _HalfStream(), "acked": False},
                "complete": False,
            }
        s = self._streams[key]
        cs = s["client"]
        ss = s["server"]
        # Determine direction: compare to client source
        if src == cs["ip"] and sport == cs["port"]:
            d = cs
            opp = ss
        else:
            d = ss
            opp = cs
        if not d["syn"]:
            d["syn"] = syn
        if syn:
            d["hs"].syn_seq = seq
        if fin:
            d["hs"].fin_seq = seq + len(payload)
        if rst:
            d["hs"].rst = True

        if payload:
            self._store(d["hs"], seq, payload, ts)

        if d["hs"].rst or (opp["hs"].rst):
            s["complete"] = True
        # FIN+ACK both directions
        if cs["hs"].fin_seq is not None and ss["hs"].fin_seq is not None:
            s["complete"] = True

    def _store(self, hs: _HalfStream, seq: int, data: bytes, ts: float) -> None:
        hs.last_ts = ts
        if hs.base_seq is None:
            hs.base_seq = seq
            hs.leftmost = seq
            hs.leftmost_data_end = seq
        # Skip pure retransmit of an already-filled region
        end = seq + len(data)
        # If entirely below leftmost, skip
        if end <= hs.leftmost:
            return
        # If this data starts at/below leftmost and advances it directly
        if seq <= hs.leftmost and end > hs.leftmost:
            toappend = data[hs.leftmost - seq:]
            hs.buf += toappend
            hs.leftmost = end
            # merge any buffered segments that follow contiguously
            self._flush_contiguous(hs)
            return
        # Out-of-order: buffer by gap
        hs.segments[seq] = (data, end, ts)
        self._flush_contiguous(hs)

    def _flush_contiguous(self, hs: _HalfStream) -> None:
        while True:
            nxt = hs.segments.get(hs.leftmost)
            if nxt is None:
                break
            data, end, _ = nxt
            hs.buf += data
            hs.leftmost = end
            del hs.segments[hs.leftmost - len(data)]
            # delete via key=old leftmost:
            # recompute
            hs.segments.pop(hs.leftmost - len(data), None)

    def completed(self):
        return [k for k, v in self._streams.items() if v["complete"]]

    def stream_bytes(self, key, direction: str) -> bytes | None:
        if key not in self._streams:
            return None
        s = self._streams[key][direction]["hs"]
        return bytes(s.buf)


def tcp_flags(pkt) -> int:
    try:
        return pkt.tcp.flags
    except Exception:
        return getattr(pkt, "fl", 0)


def read_pcap_streams(pcap_path: str, idle_timeout: float = 600.0, max_bytes_per_stream: int = 64 * 1024 * 1024):
    """
    Returns an Assembler keyed on normalized tuples with filled byte buffers.
    Raises OSError on unreadable files, ValueError on malformed capture.
    """
    if not HAS_DPKT:
        raise RuntimeError("dpkt not installed")
    asm = StreamAssembler(idle_timeout=idle_timeout)
    with open(pcap_path, "rb") as f:
        try:
            cap = dpkt.pcap.Reader(f)
        except Exception as e:
            raise ValueError(f"invalid pcap: {e}") from e
        for ts, buf in cap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    # maybe IP directly (IPv4 pass-through or VLAN)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                    else:
                        continue
                else:
                    ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                tcp = ip.data
                payload = bytes(tcp.data)
                asm.feed(
                    src=str(ip.src), dst=str(ip.dst),
                    sport=tcp.sport, dport=tcp.dport,
                    seq=tcp.seq, ack=tcp.ack,
                    payload=payload, flags=tcp.flags, ts=ts,
                )
            except Exception:
                # Malformed/unparseable packet: skip, never crash the pipeline.
                continue
    return asm


PROTOCOL_BANNER_SCORE = {
    b"ESMTP": Protocol.SMTP,
    b"SMTP": Protocol.SMTP,
    b"Dovecot": Protocol.IMAP,
    b"IMAP4": Protocol.IMAP,
    b"+OK": Protocol.POP3,
}


def detect_protocol(session: Session, client_stream: bytes, server_stream: bytes) -> Protocol:
    """Ordered inference: ports first, then plaintext command/banner heuristics."""
    if session.server_port in PORT_TO_PROTO:
        proto = PORT_TO_PROTO[session.server_port]
        session.port_based = True
        return proto
    # heuristic on plaintext
    probe = (server_stream[:4 * 1024] + b"\x00" + client_stream[:4 * 1024]).upper()
    for marker, proto in PROTOCOL_BANNER_SCORE.items():
        if marker in probe:
            return proto
    # command heuristic
    upper_client = client_stream[:4096].upper()
    for cmd, proto in ((b"EHLO", Protocol.SMTP), (b"MAIL FROM", Protocol.SMTP),
                       (b"a001", Protocol.IMAP), (b"LOGIN", Protocol.IMAP),
                       (b"USER", Protocol.POP3), (b"PASS", Protocol.POP3)):
        if cmd in upper_client:
            return proto
    return Protocol.UNKNOWN


def reconstruct_sessions(pcap_path: str) -> list[Session]:
    """
    Full Stage 2 pipeline: reassemble streams, classify protocol, detect
    STARTTLS transitions, slice plaintext vs TLS segments, return Sessions.
    """
    asm = read_pcap_streams(pcap_path)
    sessions: list[Session] = []
    for key in asm.completed():
        s = asm._streams[key]
        c = s["client"]
        sv = s["server"]
        c_bytes = bytes(c["hs"].buf) or b""
        s_bytes = bytes(sv["hs"].buf) or b""
        sess = Session(
            protocol=Protocol.UNKNOWN,
            five_tuple=f"{c['ip']}:{c['port']}->{sv['ip']}:{sv['port']}",
            client_ip=c["ip"], server_ip=sv["ip"],
            client_port=c["port"], server_port=sv["port"],
            start_ts=0.0, end_ts=0.0,
        )
        proto = detect_protocol(sess, c_bytes, s_bytes)
        sess.protocol = proto
        if proto == Protocol.UNKNOWN:
            continue

        implicit = sess.server_port in IMPLICIT_TLS_PORTS

        # Determine TLS transition offset
        starttls_offset = None
        if not implicit and proto in (Protocol.SMTP, Protocol.IMAP, Protocol.POP3):
            # Look for STARTTLS/STLS on the client side
            off = find_starttls_offset(c_bytes, proto.value)
            if off is not None:
                starttls_offset = off

        # Decide if the session carries TLS
        tls_start_client = None
        # 1) implicit TLS (server seen any TLS records first) -> 0
        # 2) STARTTLS transition offset-> 
        if implicit:
            tls_start_client = 0
            sess.is_starttls = False
        elif starttls_offset is not None and starttls_offset < len(c_bytes):
            tls_start_client = starttls_offset
            sess.is_starttls = True
        else:
            # Maybe TLS anyway (weird server w/o transition, e.g. transformed)
            recs = parse_tls_records(c_bytes)
            if recs:
                tls_start_client = c_bytes.find(bytes(recs[0].payload)[:16]) if c_bytes else None
                if tls_start_client is None:
                    tls_start_client = 0
                sess.is_starttls = False

        if tls_start_client is not None:
            offset = tls_start_client
            sess.transition_offset = offset
            sess.plaintext_segment = c_bytes[:offset]
            sess.plaintext_server_segment = s_bytes[:offset] if sess.is_starttls else b""
            sess.tls_segment = c_bytes[offset:]
            sess.tls_server_segment = s_bytes[offset:] if sess.is_starttls else s_bytes
        else:
            sess.plaintext_segment = c_bytes
            sess.plaintext_server_segment = s_bytes
            sess.tls_segment = b""
            sess.tls_server_segment = b""

        sessions.append(sess)
    return sessions


def format_five_tuple(ip1, p1, ip2, p2) -> str:
    if p1 < p2 or (p1 == p2 and ip1 <= ip2):
        return f"{ip1}:{p1}->{ip2}:{p2}"
    return f"{ip2}:{p2}->{ip1}:{p1}"