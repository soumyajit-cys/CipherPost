"""Optional DEFAULT-OFF active probe (Phase 4 Task 1).

Connects ONLY to hosts the user explicitly names (`cipherpost probe
host:port`) and records the presented certificate chain so analysts can join
it to passive TLS 1.3 observations by host. There is deliberately NO server
API for probing: it can never run from the server.

Safety: explicit host allowlist semantics (you type the target), 10 s
timeouts, at most one connection per host per 60 s (rate limit), private /
loopback / link-local ranges blocked unless allow_private=True, SNI set to
the target host. Prints a consent reminder on every run.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import time

log = logging.getLogger("cipherpost.probe")

CONSENT_NOTICE = (
    "Only probe hosts you are authorized to test (your own infrastructure "
    "or with written permission). Probing without authorization may be unlawful."
)

_last_probe: dict[str, float] = {}
MIN_INTERVAL_SECONDS = 60.0
CONNECT_TIMEOUT = 10.0


def _is_public(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # DNS name: resolved address checked after connect below
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _check_connected_public(sock: socket.socket, host: str) -> None:
    try:
        ip = ipaddress.ip_address(sock.getpeername()[0])
    except Exception:
        return
    if not (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return
    raise ValueError(f"refusing private target {host} ({ip}) without allow_private")


def _coerce_der(cert) -> bytes | None:
    """Normalize _ssl.Certificate objects, PEM, or DER to DER bytes."""
    try:
        if isinstance(cert, bytes):
            if cert.startswith(b"-----BEGIN"):
                from cryptography import x509 as _x509
                from cryptography.hazmat.primitives import serialization as _ser
                return _x509.load_pem_x509_certificate(cert).public_bytes(_ser.Encoding.DER)
            return cert
        if hasattr(cert, "public_bytes"):
            import _ssl as _sslmod
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives import serialization as _ser
            for enc in (_sslmod.ENCODING_PEM, _sslmod.ENCODING_DER):
                try:
                    blob = cert.public_bytes(enc)
                    if enc == _sslmod.ENCODING_PEM:
                        return _x509.load_pem_x509_certificate(blob).public_bytes(
                            _ser.Encoding.DER)
                    return bytes(blob)
                except Exception:
                    continue
    except Exception:
        pass
    return None


def probe_host(host: str, port: int = 25, timeout: float = CONNECT_TIMEOUT,
               allow_private: bool = False, starttls: bool = True) -> dict:
    """TLS-handshake the target and return chain metadata. Raises on refusal."""
    host = (host or "").strip().rstrip(".")
    if not host or len(host) > 253:
        raise ValueError("invalid host")
    if not (1 <= int(port) <= 65535):
        raise ValueError("invalid port")
    if not allow_private and not _is_public(host):
        raise ValueError(f"refusing non-public target {host} without allow_private")
    now = time.time()
    key = f"{host}:{port}"
    if now - _last_probe.get(key, 0.0) < MIN_INTERVAL_SECONDS:
        raise ValueError(f"rate limited: probed {key} less than 60 s ago")
    _last_probe[key] = now
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False  # we record, not validate; chain facts only
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        if not allow_private:
            _check_connected_public(raw, host)
        if starttls and int(port) in (25, 587):
            _smtp_starttls(raw, host, timeout)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        try:
            chain = tls.getpeercert(binary_form=True)
            chain_all = [_coerce_der(chain)] if chain else []
            try:
                unverified = tls._sslobj.get_unverified_chain()  # type: ignore[attr-defined]
                if unverified:
                    chain_all = [_coerce_der(c) for c in unverified]
            except Exception:
                pass
            from cryptography import x509 as _x509
            certs = []
            for der in chain_all:
                try:
                    c = _x509.load_der_x509_certificate(der)
                    try:
                        cn = c.subject.get_attributes_for_oid(
                            _x509.NameOID.COMMON_NAME)[0].value
                    except Exception:
                        cn = ""
                    certs.append({"subject_cn": cn,
                                  "not_before": c.not_valid_before_utc.isoformat(),
                                  "not_after": c.not_valid_after_utc.isoformat()})
                except Exception:
                    certs.append({"subject_cn": "<unparseable>"})
            return {"host": host, "port": int(port),
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "certs": certs, "cert_count": len(certs)}
        finally:
            try:
                tls.close()
            except Exception:
                raw.close()
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        raise


def _smtp_starttls(sock: socket.socket, host: str, timeout: float) -> None:
    sock.settimeout(timeout)
    banner = sock.recv(1024)
    if not banner.startswith(b"220"):
        raise ValueError("no SMTP banner")
    sock.sendall(b"EHLO cipherpost-probe\r\n")
    resp = b""
    while b"\r\n" not in resp and len(resp) < 4096:
        chunk = sock.recv(1024)
        if not chunk:
            break
        resp += chunk
    if b"STARTTLS" not in resp.upper():
        raise ValueError("server does not advertise STARTTLS")
    sock.sendall(b"STARTTLS\r\n")
    go = sock.recv(1024)
    if not go.startswith(b"220"):
        raise ValueError("STARTTLS not accepted (no 220)")
