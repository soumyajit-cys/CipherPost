"""
Live packet ingestion: a single normalized Packet model produced by either a
scapy live sniffer or a pcap iterator, so the reconstruction engine never
cares where packets came from.
"""
from __future__ import annotations

from dataclasses import dataclass, field

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    raw: bytes = b""          # original link-layer frame (for rolling retention)
    raw_ref: tuple | None = None   # (segment_file, offset, length) filled by writer


@dataclass
class SniffStats:
    seen: int = 0
    non_tcp: int = 0
    filtered_out: int = 0
    dropped: int = 0
    unknown_session: int = 0

    def as_dict(self) -> dict:
        return {
            "packets_seen": self.seen,
            "non_tcp": self.non_tcp,
            "filtered_out": self.filtered_out,
            "sessions_dropped": self.dropped,
            "unknown_streams": self.unknown_session,
        }


def bpf_port_filter(ports: list[int]) -> str:
    parts = []
    for p in ports:
        parts.append(f"tcp port {p}")
    return " or ".join(parts) if parts else "tcp"


def is_tcp_packet(pkt) -> bool:
    """Return True if a scapy packet is an IPv4/IPv6 TCP datagram."""
    try:
        from scapy.layers.inet import TCP, IP
        from scapy.layers.inet6 import IPv6
        if IP in pkt and TCP in pkt:
            return True
        if IPv6 in pkt and TCP in pkt:
            return True
    except Exception:
        pass
    return False


def packet_from_scapy(pkt) -> Packet | None:
    """Normalize a scapy packet into our Packet model (TCP only)."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if IP in pkt:
            ip, tcp = pkt[IP], pkt[TCP]
            src = ip.src
        elif IPv6 in pkt:
            ip, tcp = pkt[IPv6], pkt[TCP]
            src = ip.src
        else:
            return None
        return Packet(
            ts=float(pkt.time),
            src=src,
            dst=ip.dst,
            sport=int(tcp.sport),
            dport=int(tcp.dport),
            seq=int(tcp.seq),
            ack=int(tcp.ack),
            flags=int(tcp.flags),
            payload=bytes(tcp.payload),
            raw=bytes(pkt),
        )
    except Exception:
        return None


def iter_pcap_packets(path: str, only_tcp: bool = True):
    """
    Yield Packet objects from a pcap/pcapng file (dpkt). Used by replay mode
    and by the replay harness. Malformed frames are skipped, never fatal.
    """
    import dpkt
    f = open(path, "rb")
    try:
        try:
            cap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            cap = dpkt.pcapng.Reader(f)
        for ts, buf in cap:
            pkt = packet_from_dpkt(ts, buf)
            if pkt is None:
                continue
            yield pkt
    finally:
        f.close()


def packet_from_dpkt(ts: float, buf: bytes) -> Packet | None:
    """Normalize a raw link-layer frame (dpkt-ethernet style) into a Packet."""
    try:
        import dpkt
        from dpkt.ip import IP as DpktIP
        from dpkt.ip6 import IP6 as DpktIP6
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if isinstance(ip, DpktIP):
            src, dst = _ip_str(ip.src), _ip_str(ip.dst)
        elif isinstance(ip, DpktIP6):
            src, dst = ip.src, ip.dst
        else:
            return None
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            return None
        tcp = ip.data
        return Packet(
            ts=float(ts),
            src=src, dst=dst,
            sport=int(tcp.sport), dport=int(tcp.dport),
            seq=int(tcp.seq), ack=int(tcp.ack),
            flags=int(tcp.flags),
            payload=bytes(tcp.data),
            raw=buf,
        )
    except Exception:
        return None


def _ip_str(x) -> str:
    import socket
    if isinstance(x, str):
        return x
    if isinstance(x, bytes):
        try:
            return socket.inet_ntop(socket.AF_INET, x)
        except (ValueError, OSError):
            pass
        try:
            return socket.inet_ntop(socket.AF_INET6, x)
        except (ValueError, OSError):
            return x.decode(errors="replace")
    if isinstance(x, int):
        return socket.inet_ntop(socket.AF_INET, x.to_bytes(4, "big"))
    return str(x)