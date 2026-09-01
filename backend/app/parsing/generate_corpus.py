"""
Stage 1: Synthetic labeled PCAP corpus generator.

Builds realistic SMTP/IMAP/POP3 sessions with various TLS configurations,
writing each as a .pcap file plus a companion .json ground-truth metadata
file. Serves as the fixed test fixture set for all later stages.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

from scapy.all import (
    Ether, IP, TCP, Raw, PcapWriter,
)

from app.parsing.cert_utils import (
    make_root_ca, issue_leaf, make_self_signed, cert_to_pem,
    make_weak_signature_cert, pem_from_der,
)


# ---------------------------------------------------------------------------
# Cipher metadata helpers
# ---------------------------------------------------------------------------

CIPHER_REGISTRY = {
    "TLS_AES_256_GCM_SHA384": {"iana": 0x1302, "version": 0x0304, "strength": 1.0,
                               "name": "TLS_AES_256_GCM_SHA384", "kind": "aead", "pfs": True, "key_len": 256, "sig": None},
    "TLS_AES_128_GCM_SHA256": {"iana": 0x1301, "version": 0x0304, "strength": 0.95,
                               "name": "TLS_AES_128_GCM_SHA256", "kind": "aead", "pfs": True, "key_len": 128, "sig": None},
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {"iana": 0xC030, "version": 0x0303, "strength": 0.9,
                                              "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kind": "aead", "pfs": True, "key_len": 256, "sig": "rsa"},
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {"iana": 0xC02F, "version": 0x0303, "strength": 0.85,
                                              "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kind": "aead", "pfs": True, "key_len": 128, "sig": "rsa"},
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": {"iana": 0xC014, "version": 0x0303, "strength": 0.6,
                                           "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "kind": "cbc", "pfs": True, "key_len": 256, "sig": "rsa"},
    "TLS_RSA_WITH_AES_256_CBC_SHA": {"iana": 0x0035, "version": 0x0303, "strength": 0.4,
                                     "name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kind": "cbc", "pfs": False, "key_len": 256, "sig": "rsa"},
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": {"iana": 0x000A, "version": 0x0301, "strength": 0.25,
                                      "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kind": "cbc", "pfs": False, "key_len": 112, "sig": "rsa"},
    "TLS_RSA_WITH_RC4_128_SHA": {"iana": 0x0005, "version": 0x0301, "strength": 0.05,
                                 "name": "TLS_RSA_WITH_RC4_128_SHA", "kind": "stream", "pfs": False, "key_len": 128, "sig": "rsa"},
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5": {"iana": 0x0003, "version": 0x0300, "strength": 0.0,
                                       "name": "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "kind": "stream", "pfs": False, "key_len": 40, "sig": "rsa"},
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {"iana": 0xC02B, "version": 0x0303, "strength": 0.85,
                                                "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kind": "aead", "pfs": True, "key_len": 128, "sig": "ecdsa"},
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": {"iana": 0x0039, "version": 0x0303, "strength": 0.55,
                                         "name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "kind": "cbc", "pfs": True, "key_len": 256, "sig": "rsa"},
}


def cipher_iana(name: str) -> int:
    return CIPHER_REGISTRY[name]["iana"]


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------

@dataclass
class GenSession:
    name: str
    protocol: str          # SMTP | IMAP | POP3
    port: int
    use_starttls: bool
    tls_version: float
    cipher: str
    cert_mode: str         # valid | self-signed | expired | untrusted | weak-sig | short-key
    sni: str = "mail.cipherpost.test"
    client_ip: str = "192.168.1.10"
    server_ip: str = "192.168.1.20"
    expected_findings: list[str] = None

    def __post_init__(self):
        if self.expected_findings is None:
            self.expected_findings = []


# ---------------------------------------------------------------------------
# Low-level packet builders
# ---------------------------------------------------------------------------

def build_pkt(src, dst, sport, dport, seq, ack, payload: Optional[bytes], flags="PA", ts=1000.0):
    p = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535
    )
    if payload and len(payload) > 0:
        p = p / Raw(load=payload)
    p.time = ts
    return p


# ---------------------------------------------------------------------------
# TLS record builders (raw bytes we control to encode handshake data)
# ---------------------------------------------------------------------------

# Use scapy's TLS layer for the realistic handshake construction where
# possible, but pass cert bytes manually.

def tls_record(handshake_bytes: bytes, content_type: int = 22, version: int = 0x0303) -> bytes:
    rec = len(handshake_bytes).to_bytes(2, "big")
    return bytes([content_type, version >> 8 & 0xFF, version & 0xFF]) + rec + handshake_bytes


def build_client_hello(tls_version: int, cipher_suites: list[int], sni: str,
                       groups: list[int] = None, alpn: list[bytes] = None) -> bytes:
    # Handshake header: type(1) length(3)
    body = bytearray()

    # client_version
    body += tls_version.to_bytes(2, "big")

    # random 32 bytes
    body += bytes(range(32))

    # session id (empty)
    body += b"\x00"

    # cipher suites: length + suites
    suites = []
    for cs in set(cipher_suites):
        suites += cs.to_bytes(2, "big")
    body += len(suites).to_bytes(2, "big") + bytes(suites)

    # compression methods
    body += b"\x01\x00"

    # extensions
    ext = bytearray()

    # SNI
    sni_b = sni.encode()
    sni_list = (0x00 + len(sni_b)).to_bytes(2, "big") + sni_b
    sni_len = len(sni_list).to_bytes(2, "big")
    ext += (0).to_bytes(2, "big") + (4 + len(sni_b)).to_bytes(2, "big") + sni_list

    # supported groups (for PFS)
    if groups:
        groups_b = b"".join(g.to_bytes(2, "big") for g in groups)
        ext += (10).to_bytes(2, "big") + (len(groups_b) + 2).to_bytes(2, "big") + len(groups_b).to_bytes(2, "big") + groups_b

    # ALPN
    if alpn:
        alpn_b = b"".join(bytes([len(p)]) + p for p in alpn)
        alpn_len = len(alpn_b).to_bytes(2, "big")
        ext += (16).to_bytes(2, "big") + (len(alpn_b) + 2).to_bytes(2, "big") + alpn_len + alpn_b

    # signature algorithms (needed for some servers)
    sig_list = b"\x04\x03\x04\x01\x02\x03\x02\x01"
    ext += (13).to_bytes(2, "big") + (len(sig_list) + 2).to_bytes(2, "big") + len(sig_list).to_bytes(2, "big") + sig_list

    # extension block
    body += len(ext).to_bytes(2, "big") + bytes(ext)

    h = bytearray()
    hs_len = len(body)
    hdr = bytes([1]) + hs_len.to_bytes(3, "big")
    return bytes(h) + hdr + bytes(body)


def build_server_hello(tls_version: int, cipher_suite: int) -> bytes:
    body = bytearray()
    body += tls_version.to_bytes(2, "big")  # server version
    body += bytes(range(32, 64))  # random
    body += b"\x00"  # session id empty
    body += cipher_suite.to_bytes(2, "big")
    body += b"\x00"  # compression
    # extensions: supported_versions for TLS 1.3
    if tls_version >= 0x0304:
        ext = bytearray()
        ext += (43).to_bytes(2, "big")
        ext += (3).to_bytes(2, "big")
        ext += bytes([2]) + tls_version.to_bytes(2, "big")
        body += len(ext).to_bytes(2, "big") + ext
    hs = bytearray()
    hs_len = len(body)
    hs += bytes([2]) + hs_len.to_bytes(3, "big") + body
    return tls_record(bytes(hs), version=tls_version if tls_version > 0x0300 else 0x0301)


def build_certificate_message(cert_pems: list[bytes], tls13: bool = False) -> bytes:
    body = bytearray()
    cert_chain = bytearray()
    for pem in cert_pems:
        der_start = pem.find(b"-----BEGIN CERTIFICATE-----\n")
        if der_start >= 0:
            # DER = base64 between markers
            import base64, re
            mm = re.search(rb"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----", pem, re.S)
            der = base64.b64decode(re.sub(rb"\s+", b"", mm.group(1)))
        else:
            der = pem
        if tls13:
            # length-prefixed entry with 3-byte length prefix, 0 extensions
            der_len = len(der).to_bytes(3, "big")
            cert_chain += der_len + der + (0).to_bytes(2, "big")
        else:
            der_len = len(der).to_bytes(3, "big")
            cert_chain += der_len + der
    if tls13:
        length = (1 + len(cert_chain)).to_bytes(3, "big")
        body += length + bytes([1]) + cert_chain
    else:
        body += len(cert_chain).to_bytes(3, "big") + cert_chain
    hs = bytearray([11]) + len(body).to_bytes(3, "big") + body
    return tls_record(bytes(hs), version=0x0303)


def build_certificate_request() -> bytes:
    return b""


def build_server_hello_done() -> bytes:
    return tls_record(bytes([14, 0, 0, 0]), version=0x0303)


def build_change_cipher_spec(version: int = 0x0303) -> bytes:
    return bytes([20, version >> 8 & 0xFF, version & 0xFF, 0x00, 0x01, 0x01])


def build_encrypted_handshake(version: int = 0x0303, junk: bytes = None) -> bytes:
    if junk is None:
        junk = bytes(range(40))
    return bytes([23, version >> 8 & 0xFF, version & 0xFF]) + len(junk).to_bytes(2, "big") + junk


# ---------------------------------------------------------------------------
# Session / stream builders
# ---------------------------------------------------------------------------

class StreamBuilder:
    """
    Builds a bidirectional TCP stream with proper sequence/ack bookkeeping
    and optional packet fragmentation/retransmission to exercise reassembly.
    """

    def __init__(self, proto: str, sport: int, dport: int, src="192.168.1.10", dst="192.168.1.20",
                 frag_size: Optional[int] = None, ts0=1000.0):
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.src = src
        self.dst = dst
        self.frag_size = frag_size
        self.ts0 = ts0
        self.seq = {"c": 1000, "s": 5000}
        self.ack = {"c": 5000, "s": 1000}
        self.sup = 0
        self.sack = 0
        self.packets = []
        self.cmd_counter = 0
        self._ts = ts0

    def _next_ts(self):
        self._ts += 0.01
        return self._ts

    def client_talk(self, payload: bytes, frag: bool = False, retransmit_seq: Optional[int] = None):
        """Send data from client to server."""
        if self.frag_size and len(payload) > self.frag_size:
            chunks = [payload[i:i+self.frag_size] for i in range(0, len(payload), self.frag_size)]
        else:
            chunks = [payload]
        for chunk in chunks:
            # handle out-of-order: swap last two chunks sent latest
            if len(chunks) > 2 and chunks.index(chunk) == len(chunks) - 2:
                continue  # used for ooo simulation upstream
            seq = self.seq["c"]
            self.sup += len(chunk)
            self.seq["c"] += len(chunk)
            self.packets.append(build_pkt(self.src, self.dst, self.sport, self.dport,
                                          seq, self.ack["s"], chunk, ts=self._next_ts()))
        # update ack that we've received everything the server has sent
        self.ack["c"] = self.sack
        return self

    def server_talk(self, payload: bytes):
        chunks = [payload[i:i+self.frag_size] for i in range(0, len(payload), self.frag_size)] if self.frag_size and len(payload) > self.frag_size else [payload]
        for chunk in chunks:
            seq = self.seq["s"]
            self.sack += len(chunk)
            self.seq["s"] += len(chunk)
            self.packets.append(build_pkt(self.dst, self.src, self.dport, self.sport,
                                          seq, self.ack["c"], chunk, ts=self._next_ts()))
        self.ack["s"] = self.sup
        return self

    def client_ack(self):
        self.ack["c"] = self.sack
        self.packets.append(build_pkt(self.src, self.dst, self.sport, self.dport,
                                      self.seq["c"], self.ack["s"], None, flags="A", ts=self._next_ts()))
        return self

    def server_ack(self):
        self.packets.append(build_pkt(self.dst, self.src, self.dport, self.sport,
                                      self.seq["s"], self.ack["c"], None, flags="A", ts=self._next_ts()))
        return self

    def fin(self):
        self.packets.append(build_pkt(self.src, self.dst, self.sport, self.dport,
                                      self.seq["c"], self.ack["s"], None, flags="FA", ts=self._next_ts()))
        self.packets.append(build_pkt(self.dst, self.src, self.dport, self.sport,
                                      self.seq["s"], self.ack["c"], None, flags="FA", ts=self._next_ts()))
        return self


def make_email_body(proto: str):
    if proto == "SMTP":
        return (
            "EHLO client.example.com\r\n"
            "MAIL FROM:<sender@example.com>\r\n"
            'RCPT TO:<recipient@example.com>\r\n'
            "DATA\r\n"
            "Subject: Test message\r\n"
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "\r\n"
            "This is a test email body.\r\n"
            ".\r\n"
            "QUIT\r\n"
        )
    if proto == "IMAP":
        return (
            "a001 LOGIN user@example.com password123\r\n"
            "a002 SELECT INBOX\r\n"
            "a003 FETCH 1 BODY[]\r\n"
            "a004 LOGOUT\r\n"
        )
    # POP3
    return (
        "USER recipient@example.com\r\n"
        "PASS password123\r\n"
        "STAT\r\n"
        "LIST\r\n"
        "QUIT\r\n"
    )


# ---------------------------------------------------------------------------
# Ground-truth generation
# ---------------------------------------------------------------------------

def tls_version_label(ver: float) -> str:
    return {
        0x0300: "SSLv3",
        0x0301: "TLS1.0",
        0x0302: "TLS1.1",
        0x0303: "TLS1.2",
        0x0304: "TLS1.3",
    }.get(ver, f"UNKNOWN-{ver}")


def generate_session(sess: GenSession, outdir: str):
    """Generate a pcap + json ground truth pair for a single session scenario."""
    # Create certs for this session
    root_cert = None
    root_key = None
    cert_pem = None
    if sess.cert_mode == "valid":
        root_cert, root_key = make_root_ca("CipherPost Root CA")
        leaf, _ = issue_leaf(root_cert, root_key, cn=sess.sni)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem, cert_to_pem(root_cert)]
    elif sess.cert_mode == "self-signed":
        leaf, _ = make_self_signed(cn=sess.sni)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem]
    elif sess.cert_mode == "expired":
        root_cert, root_key = make_root_ca("CipherPost Root CA")
        leaf, _ = issue_leaf(root_cert, root_key, cn=sess.sni, days_valid=-30, not_before_offset_days=900)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem, cert_to_pem(root_cert)]
    elif sess.cert_mode == "untrusted":
        # signed by CA not in our trust store
        other_root, other_key = make_root_ca("Evil Corp CA")
        leaf, _ = issue_leaf(other_root, other_key, cn=sess.sni)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem, cert_to_pem(other_root)]
    elif sess.cert_mode == "weak-sig":
        der, _ = make_weak_signature_cert(cn=sess.sni)
        leaf_pem = pem_from_der(der)
        root_cert, root_key = make_root_ca("CipherPost Root CA")
        cert_pem = leaf_pem
        chain_pem = [leaf_pem, cert_to_pem(root_cert)]
    elif sess.cert_mode == "short-key":
        root_cert, root_key = make_root_ca("CipherPost Root CA")
        leaf, _ = issue_leaf(root_cert, root_key, cn=sess.sni, key_size=1024)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem, cert_to_pem(root_cert)]
    else:
        leaf, _ = make_self_signed(cn=sess.sni)
        cert_pem = cert_to_pem(leaf)
        chain_pem = [cert_pem]

    # Build stream
    stream = StreamBuilder(sess.protocol, sport=10000 + hash(sess.name) % 5000, dport=sess.port,
                           frag_size=None)
    stream.client_talk(b"")
    # Protocol banner
    banners = {
        "SMTP": b"220 mail.cipherpost.test ESMTP Postfix\r\n",
        "IMAP": b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n",
        "POP3": b"+OK Dovecot ready.\r\n",
    }
    stream.server_talk(banners[sess.protocol])

    x509_cert_field = b"" if sess.cert_mode == "untrusted" else b""

    if sess.use_starttls:
        # Plaintext STARTTLS negotiation
        if sess.protocol == "SMTP":
            stream.client_talk(b"EHLO client.example.com\r\n")
            stream.server_talk(b"250-mail.cipherpost.test\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
            stream.client_talk(b"STARTTLS\r\n")
            stream.server_talk(b"220 2.0.0 Ready to start TLS\r\n")
        elif sess.protocol == "IMAP":
            stream.client_talk(b"a001 CAPABILITY\r\n")
            stream.server_talk(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n")
            stream.client_talk(b"a002 STARTTLS\r\n")
            stream.server_talk(b"a002 OK Begin TLS negotiation now\r\n")
        else:  # POP3
            stream.client_talk(b"STLS\r\n")
            stream.server_talk(b"+OK Begin TLS negotiation now\r\n")

    # TLS handshake (both for explicit STARTTLS and implicit 465/993/995)
    is_tls13 = sess.tls_version >= 0x0304

    # ClientHello
    client_groups = [29, 23]  # x25519, secp256r1
    client_hello = build_client_hello(
        tls_version=sess.tls_version,
        cipher_suites=[cipher_iana(sess.cipher)],
        sni=sess.sni,
        groups=client_groups if sess.tls_version >= 0x0303 else None,
        alpn=[b"smtp", b"imap", b"pop3"] if is_tls13 else None,
    )
    stream.client_talk(client_hello)
    stream.server_talk(build_server_hello(sess.tls_version, cipher_iana(sess.cipher)))

    # Certificate(s)
    stream.server_talk(build_certificate_message(chain_pem, tls13=is_tls13))

    if not is_tls13:
        if sess.protocol == "SMTP":
            stream.server_talk(build_certificate_request())
        stream.server_talk(build_server_hello_done())

        # Client key exchange - simplified dummy bytes (real would be encrypted premaster)
        client_kex = bytes([16, 0, 0, 2, 0, 1])
        stream.client_talk(tls_record(client_kex, version=sess.tls_version))
        stream.client_talk(build_change_cipher_spec(version=sess.tls_version))
        stream.client_talk(build_encrypted_handshake(version=sess.tls_version))

    # Server CCS + Finished (TLS1.3 similar)
    stream.server_talk(build_change_cipher_spec(version=sess.tls_version))
    stream.server_talk(build_encrypted_handshake(version=sess.tls_version))

    if is_tls13:
        stream.client_talk(build_change_cipher_spec(version=sess.tls_version))
        stream.client_talk(build_encrypted_handshake(version=sess.tls_version))
        stream.server_talk(build_encrypted_handshake(version=sess.tls_version))

    # Now the encrypted app data - dummy bytes
    if sess.protocol == "SMTP":
        stream.client_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"a"*40))
        stream.server_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"b"*40))
    elif sess.protocol == "IMAP":
        stream.client_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"c"*40))
        stream.server_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"d"*40))
    else:  # POP3
        stream.client_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"e"*40))
        stream.server_talk(build_encrypted_handshake(version=sess.tls_version, junk=bytes([0x17]) + b"\x03\x03" + b"f"*40))

    stream.fin()

    # Write pcap
    pcap_path = os.path.join(outdir, f"{sess.name}.pcap")
    with PcapWriter(pcap_path, append=True, sync=True) as w:
        for p in stream.packets:
            w.write(p)

    # Ground truth metadata
    cipher_meta = CIPHER_REGISTRY[sess.cipher]
    truth = {
        "name": sess.name,
        "protocol": sess.protocol,
        "port": sess.port,
        "client_ip": sess.client_ip,
        "server_ip": sess.server_ip,
        "client_port": stream.sport,
        "server_port": sess.port,
        "use_starttls": sess.use_starttls,
        "implicit_tls": (sess.port in (465, 993, 995)),
        "tls_version": tls_version_label(sess.tls_version),
        "tls_version_raw": sess.tls_version,
        "cipher": sess.cipher,
        "cipher_suite_iana": hex(cipher_iana(sess.cipher)),
        "cipher_strength": cipher_meta["strength"],
        "pfs": cipher_meta["pfs"],
        "key_len": cipher_meta["key_len"],
        "cert_mode": sess.cert_mode,
        "sni": sess.sni,
        "expected_findings": sorted(sess.expected_findings),
        "clean": not sess.expected_findings,
        "file_hash": hashlib.sha256(open(pcap_path, "rb").read()).hexdigest(),
    }
    with open(os.path.join(outdir, f"{sess.name}.json"), "w") as f:
        json.dump(truth, f, indent=2)

    return truth


# ---------------------------------------------------------------------------
# Corpus definition
# ---------------------------------------------------------------------------

def define_corpus() -> list[GenSession]:
    corpus = []
    # Basic classifications
    corpus.append(GenSession(
        name="smtp_tls13_strong", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0304, cipher="TLS_AES_256_GCM_SHA384", cert_mode="valid",
        expected_findings=["tls-1-3-strong"],
    ))
    corpus.append(GenSession(
        name="imap_tls13_strong", protocol="IMAP", port=993, use_starttls=False,
        tls_version=0x0304, cipher="TLS_AES_128_GCM_SHA256", cert_mode="valid",
        expected_findings=["tls-1-3-strong"],
    ))
    corpus.append(GenSession(
        name="pop3_tls12_acceptable", protocol="POP3", port=995, use_starttls=False,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cert_mode="valid",
        expected_findings=["tls-1-2-ecdhe-aead"],
    ))
    corpus.append(GenSession(
        name="smtp_tls12_starttls", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", cert_mode="valid",
        expected_findings=["tls-1-2-ecdhe-aead"],
    ))
    corpus.append(GenSession(
        name="imap_tls10_weak", protocol="IMAP", port=143, use_starttls=True,
        tls_version=0x0301, cipher="TLS_RSA_WITH_RC4_128_SHA", cert_mode="valid",
        expected_findings=["tls-1-0", "rc4", "non-pfs", "weak-cipher"],
    ))
    corpus.append(GenSession(
        name="pop3_export_cipher", protocol="POP3", port=110, use_starttls=True,
        tls_version=0x0300, cipher="TLS_RSA_EXPORT_WITH_RC4_40_MD5", cert_mode="self-signed",
        expected_findings=["tls-sslv3", "export-cipher", "non-pfs", "weak-cipher", "self-signed"],
    ))
    corpus.append(GenSession(
        name="smtp_expired_cert", protocol="SMTP", port=465, use_starttls=False,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cert_mode="expired",
        expected_findings=["expired-cert", "untrusted"],
    ))
    corpus.append(GenSession(
        name="imap_selfsigned", protocol="IMAP", port=993, use_starttls=False,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cert_mode="self-signed",
        expected_findings=["self-signed", "untrusted"],
    ))
    corpus.append(GenSession(
        name="smtp_untrusted_chain", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0303, cipher="TLS_RSA_WITH_AES_256_CBC_SHA", cert_mode="untrusted",
        expected_findings=["untrusted", "non-pfs"],
    ))
    corpus.append(GenSession(
        name="smtp_weak_sig", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cert_mode="weak-sig",
        expected_findings=["weak-signature"],
    ))
    corpus.append(GenSession(
        name="smtp_short_key", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0303, cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cert_mode="short-key",
        expected_findings=["short-key"],
    ))
    corpus.append(GenSession(
        name="pop3_tls12_nonpfs", protocol="POP3", port=995, use_starttls=False,
        tls_version=0x0303, cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA", cert_mode="valid",
        expected_findings=["non-pfs", "weak-cipher"],
    ))
    corpus.append(GenSession(
        name="smtp_tls12_rc4", protocol="SMTP", port=587, use_starttls=True,
        tls_version=0x0303, cipher="TLS_RSA_WITH_RC4_128_SHA", cert_mode="valid",
        expected_findings=["rc4", "non-pfs", "weak-cipher"],
    ))
    corpus.append(GenSession(
        name="imap_tls12_3des", protocol="IMAP", port=143, use_starttls=True,
        tls_version=0x0303, cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA", cert_mode="valid",
        expected_findings=["non-pfs", "weak-cipher"],
    ))
    return corpus


def generate_corpus(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    corpus = define_corpus()
    all_truth = []
    for sess in corpus:
        truth = generate_session(sess, outdir)
        all_truth.append(truth)
        print(f"  generated {sess.name}")
    with open(os.path.join(outdir, "corpus_index.json"), "w") as f:
        json.dump({"sessions": len(all_truth), "files": all_truth}, f, indent=2)
    return all_truth


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"
    print(f"Generating CipherPost test corpus into {target} ...")
    generate_corpus(target)
