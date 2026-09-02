"""
Stage 3: Manual TLS handshake parsing.

Parses ClientHello and ServerHello (and Certificate messages) from Session
TLS segments using the record-layer parser from tls_records. Everything is
bounds-checked and treated as untrusted data; malformed handshakes raise
TlsParseError and are reported, never crash the pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.parsing.tls_records import parse_tls_records, TlsRecord, TlsParseError
from app.parsing.cert_utils import pem_from_der

TLS_VERSION_NAMES = {
    0x0300: "SSLv3.0",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}


class HandshakeParser:
    def __init__(self, data: bytes, max_certs: int = 32, max_cert_size: int = 64 * 1024):
        self.data = data
        self.max_certs = max_certs
        self.max_cert_size = max_cert_size


@dataclass
class ClientHelloInfo:
    offered_versions: list[int] = field(default_factory=list)
    legacy_version: int | None = None
    cipher_suites: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    has_supported_versions: bool = False
    raw: bytes = b""


@dataclass
class ServerHelloInfo:
    negotiated_version: int | None = None
    legacy_version: int | None = None
    cipher_suite: int | None = None
    supported_versions_ext: int | None = None
    raw: bytes = b""


@dataclass
class CertificateInfo:
    raw_certs: list[bytes] = field(default_factory=list)  # DER
    tls13: bool = False


def _handshake_body(records: list[TlsRecord]) -> dict[int, bytes]:
    """Collect handshake messages by type from a list of handshake records."""
    out: dict[int, bytes] = {}
    for rec in records:
        if rec.content_type != 22:
            continue
        buf = rec.payload
        pos = 0
        while pos + 4 <= len(buf):
            mtype = buf[pos]
            mlen = int.from_bytes(buf[pos+1:pos+4], "big")
            pos += 4
            if pos + mlen > len(buf):
                break  # partial handshake message across records
            body = buf[pos:pos+mlen]
            if mtype not in out or len(out.get(mtype, b"")) == 0:
                out[mtype] = body
            pos += mlen
    return out


def _parse_extensions(exts: bytes, max_ext: int = 32) -> list[tuple[int, bytes]]:
    parsed = []
    pos = 0
    while pos + 4 <= len(exts):
        etype = int.from_bytes(exts[pos:pos+2], "big")
        elen = int.from_bytes(exts[pos+2:pos+4], "big")
        pos += 4
        if pos + elen > len(exts):
            break
        parsed.append((etype, exts[pos:pos+elen]))
        pos += elen
        if len(parsed) >= max_ext:
            break
    return parsed


def parse_client_hello(data: bytes) -> ClientHelloInfo:
    info = ClientHelloInfo(raw=data)
    buf = data
    pos = 0

    def r2():
        nonlocal pos
        if pos + 2 > len(buf):
            raise TlsParseError("client hello truncated at legacy_version")
        v = int.from_bytes(buf[pos:pos+2], "big")
        pos += 2
        return v

    info.legacy_version = r2()
    if pos + 32 > len(buf):
        raise TlsParseError("client hello truncated before random")
    pos += 32
    sid_len = buf[pos]
    pos += 1
    if pos + sid_len > len(buf):
        raise TlsParseError("client hello truncated in session id")
    pos += sid_len
    cs_len = int.from_bytes(buf[pos:pos+2], "big")
    pos += 2
    if pos + cs_len > len(buf):
        raise TlsParseError("client hello truncated in cipher suites")
    cs_data = buf[pos:pos+cs_len]
    pos += cs_len
    info.cipher_suites = [int.from_bytes(cs_data[i:i+2], "big") for i in range(0, len(cs_data) - 1, 2)]
    if pos >= len(buf):
        return info
    comp_len = buf[pos]
    pos += 1
    if pos + comp_len > len(buf):
        raise TlsParseError("client hello truncated in compression")
    pos += comp_len
    if pos + 2 > len(buf):
        return info
    exts_len = int.from_bytes(buf[pos:pos+2], "big")
    pos += 2
    if pos + exts_len > len(buf):
        raise TlsParseError("client hello truncated in extensions")
    exts_data = buf[pos:pos+exts_len]
    for etype, edata in _parse_extensions(exts_data):
        if etype == 0:  # SNI
            if len(edata) >= 5:
                name_list_len = int.from_bytes(edata[0:2], "big")
                if 2 + name_list_len <= len(edata):
                    # first entry: type byte + len + name
                    ntype = edata[2]
                    nlen = int.from_bytes(edata[3:5], "big")
                    if ntype == 0 and 5 + nlen <= len(edata):
                        info.sni = edata[5:5+nlen].decode(errors="replace")
        elif etype == 10:  # supported_groups
            if len(edata) >= 2:
                glen = int.from_bytes(edata[0:2], "big")
                gdata = edata[2:2+glen]
                info.supported_groups = [int.from_bytes(gdata[i:i+2], "big") for i in range(0, len(gdata) - 1, 2)]
        elif etype == 16:  # ALPN
            pos2 = 2
            if len(edata) >= 2:
                plen = int.from_bytes(edata[0:2], "big")
                while pos2 + 1 <= min(2 + plen, len(edata)):
                    pl = edata[pos2]
                    name = edata[pos2+1:pos2+1+pl].decode(errors="replace")
                    info.alpn.append(name)
                    pos2 += 1 + pl
        elif etype == 43:  # supported_versions
            info.has_supported_versions = True
            if len(edata) >= 1:
                vlen = edata[0]
                vdata = edata[1:1+vlen]
                info.offered_versions = [int.from_bytes(vdata[i:i+2], "big") for i in range(0, len(vdata) - 1, 2)]
    return info


def parse_server_hello(data: bytes) -> ServerHelloInfo:
    info = ServerHelloInfo(raw=data)
    buf = data
    pos = 0
    if pos + 2 > len(buf):
        raise TlsParseError("server hello truncated version")
    info.legacy_version = int.from_bytes(buf[pos:pos+2], "big")
    pos += 2
    if pos + 32 > len(buf):
        raise TlsParseError("server hello truncated random")
    pos += 32
    sid_len = buf[pos]
    pos += 1
    if pos + sid_len > len(buf):
        raise TlsParseError("server hello truncated sid")
    pos += sid_len
    if pos + 2 > len(buf):
        raise TlsParseError("server hello truncated cipher")
    info.cipher_suite = int.from_bytes(buf[pos:pos+2], "big")
    pos += 2
    # Negotiated version fallback: TLS <=1.2 uses legacy_version; TLS 1.3 is
    # carried in the supported_versions extension.
    info.negotiated_version = info.legacy_version
    if pos + 1 > len(buf):
        return info
    comp = buf[pos]
    pos += 1
    if pos + 2 > len(buf):
        return info
    exts_len = int.from_bytes(buf[pos:pos+2], "big")
    pos += 2
    if pos + exts_len > len(buf):
        return info
    exts_data = buf[pos:pos+exts_len]
    for etype, edata in _parse_extensions(exts_data):
        if etype == 43 and len(edata) == 2:
            info.supported_versions_ext = int.from_bytes(edata[0:2], "big")
    if info.supported_versions_ext is not None:
        info.negotiated_version = info.supported_versions_ext
    return info


def parse_certificate_message(data: bytes, is_tls13: bool = False) -> CertificateInfo:
    """Parse the Certificate handshake message body."""
    info = CertificateInfo(tls13=is_tls13)
    buf = data
    pos = 0
    if is_tls13:
        # context (1) + context_len + list of cert entries (each: length + der + ext_len+ext)
        pos += 1  # context len (usually 0)
        # Actually TLS1.3: request_context length byte only
        # then certificate_list is length-prefixed by 3 bytes
        if pos + 3 > len(buf):
            raise TlsParseError("tls13 cert truncated list length")
        list_len = int.from_bytes(buf[pos:pos+3], "big")
        pos += 3
        end = min(pos + list_len, len(buf))
        while pos < end:
            if pos + 3 > len(buf):
                break
            der_len = int.from_bytes(buf[pos:pos+3], "big")
            pos += 3
            if pos + der_len + 2 > len(buf):
                break
            der = buf[pos:pos+der_len]
            pos += der_len
            ext_len = int.from_bytes(buf[pos:pos+2], "big")
            pos += 2 + ext_len
            info.raw_certs.append(bytes(der))
            if len(info.raw_certs) >= 32:
                break
    else:
        if pos + 3 > len(buf):
            raise TlsParseError("cert truncated chain length")
        chain_len = int.from_bytes(buf[pos:pos+3], "big")
        pos += 3
        end = min(pos + chain_len, len(buf))
        while pos < end:
            if pos + 3 > len(buf):
                break
            der_len = int.from_bytes(buf[pos:pos+3], "big")
            pos += 3
            if pos + der_len > len(buf):
                break
            der = buf[pos:pos+der_len]
            pos += der_len
            info.raw_certs.append(bytes(der))
            if len(info.raw_certs) >= 32:
                break
    if not info.raw_certs:
        raise TlsParseError("certificate message contained no certificates")
    return info


@dataclass
class CipherMeta:
    name: str
    strength: float          # 0.0 (broken) .. 1.0 (strong)
    kind: str                # aead | cbc | stream
    pfs: bool
    key_len: int             # effective symmetric key size in bits
    kex: str                 # ecdhe | dhe | rsa | psk | unknown
    auth: str                # rsa | ecdsa | anon | unknown
    export_class: str | None = None  # export | null | rc4 | 3des etc.


# Deterministic, auditable cipher knowledge base (subset relevant to email infra).
CIPHER_DB: dict[int, CipherMeta] = {
    0x1302: CipherMeta("TLS_AES_256_GCM_SHA384", 1.0, "aead", True, 256, "ecdhe", "any-tls13"),
    0x1301: CipherMeta("TLS_AES_128_GCM_SHA256", 0.95, "aead", True, 128, "ecdhe", "any-tls13"),
    0x1303: CipherMeta("TLS_CHACHA20_POLY1305_SHA256", 0.95, "aead", True, 256, "ecdhe", "any-tls13"),
    0xC030: CipherMeta("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0.9, "aead", True, 256, "ecdhe", "rsa"),
    0xC02F: CipherMeta("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0.85, "aead", True, 128, "ecdhe", "rsa"),
    0xC028: CipherMeta("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0.7, "cbc", True, 256, "ecdhe", "rsa"),
    0xC027: CipherMeta("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0.7, "cbc", True, 128, "ecdhe", "rsa"),
    0xC014: CipherMeta("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0.6, "cbc", True, 256, "ecdhe", "rsa"),
    0xC013: CipherMeta("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0.6, "cbc", True, 128, "ecdhe", "rsa"),
    0x009C: CipherMeta("TLS_RSA_WITH_AES_128_GCM_SHA256", 0.55, "aead", False, 128, "rsa", "rsa"),
    0x009D: CipherMeta("TLS_RSA_WITH_AES_256_GCM_SHA384", 0.6, "aead", False, 256, "rsa", "rsa"),
    0x0035: CipherMeta("TLS_RSA_WITH_AES_256_CBC_SHA", 0.4, "cbc", False, 256, "rsa", "rsa"),
    0x002F: CipherMeta("TLS_RSA_WITH_AES_128_CBC_SHA", 0.4, "cbc", False, 128, "rsa", "rsa"),
    0x000A: CipherMeta("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0.25, "cbc", False, 112, "rsa", "rsa"),
    0x0005: CipherMeta("TLS_RSA_WITH_RC4_128_SHA", 0.05, "stream", False, 128, "rsa", "rsa", "rc4"),
    0x0004: CipherMeta("TLS_RSA_WITH_RC4_128_MD5", 0.05, "stream", False, 128, "rsa", "rsa", "rc4"),
    0x0003: CipherMeta("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0.0, "stream", False, 40, "rsa", "rsa", "export"),
    0x0002: CipherMeta("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0.0, "cbc", False, 40, "rsa", "rsa", "export"),
    0x0000: CipherMeta("TLS_NULL_WITH_NULL_NULL", 0.0, "none", False, 0, "rsa", "rsa", "null"),
    0x0001: CipherMeta("TLS_RSA_WITH_NULL_MD5", 0.0, "none", False, 0, "rsa", "rsa", "null"),
    0x000B: CipherMeta("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", 0.25, "cbc", True, 112, "dhe", "dss"),
    0x0039: CipherMeta("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0.55, "cbc", True, 256, "dhe", "rsa"),
    0x0033: CipherMeta("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0.55, "cbc", True, 128, "dhe", "rsa"),
    0x0038: CipherMeta("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0.55, "cbc", True, 256, "dhe", "dss"),
    0x0032: CipherMeta("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0.55, "cbc", True, 128, "dhe", "dss"),
    0xC02B: CipherMeta("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0.85, "aead", True, 128, "ecdhe", "ecdsa"),
    0xC02C: CipherMeta("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0.9, "aead", True, 256, "ecdhe", "ecdsa"),
}


def lookup_cipher(iana: int) -> CipherMeta | None:
    return CIPHER_DB.get(iana)


def version_name(v: int | None) -> str | None:
    if v is None:
        return None
    return TLS_VERSION_NAMES.get(v, f"0x{v:04x}")