"""Convert Linux-cooked (SLL) capture to Ethernet by rewriting LINK HEADERS ONLY.

Reads a classic-pcap file with SLL encapsulation, replaces each packet's SLL
header with a synthetic Ethernet header (zero MACs, ethertype from the SLL
protocol field), and writes classic-pcap. IP/TCP/TLS payload bytes are copied
verbatim — no dissection, no reassembly, no content changes.

Usage: python3 scripts/sll_to_ether.py in.pcap out.pcap
Lab use only (Item 3): `-i any` captures reliably on this host while `-i lo`
intermittently misses loopback flows for an undetermined host reason
(documented in docs/evidence/real-eval.md); dpkt cannot parse SLL.
"""
from __future__ import annotations

import struct
import sys

PCAP_GLOBAL = 24
DLT_LINUX_SLL = 113
DLT_EN10MB = 1
SLL_HDR = 16
ETH_HDR = 14


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        blob = f.read()
    if len(blob) < PCAP_GLOBAL:
        raise SystemExit("input too short")
    magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, network = struct.unpack(
        "<IHHIIII", blob[:PCAP_GLOBAL])
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise SystemExit(f"not a classic pcap (magic {magic:#x})")
    if network != DLT_LINUX_SLL:
        raise SystemExit(f"input is not SLL (dlt={network}); refusing to convert")
    out = [struct.pack("<IHHIIII", magic, ver_maj, ver_min, thiszone,
                       sigfigs, snaplen, DLT_EN10MB)]
    off = PCAP_GLOBAL
    n = 0
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", blob[off:off + 16])
        pkt = blob[off + 16:off + 16 + incl]
        if len(pkt) < SLL_HDR:
            break
        proto = struct.unpack(">H", pkt[14:16])[0]
        ethertype = proto  # SLL protocol == ethertype for IP; copied verbatim
        eth = b"\x00" * 12 + struct.pack(">H", ethertype)
        body = pkt[SLL_HDR:]
        out.append(struct.pack("<IIII", ts_sec, ts_usec, len(eth) + len(body),
                               len(eth) + len(body)))
        out.append(eth + body)
        off += 16 + incl
        n += 1
    with open(dst, "wb") as f:
        f.write(b"".join(out))
    print(f"converted {n} packets SLL->Ethernet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
