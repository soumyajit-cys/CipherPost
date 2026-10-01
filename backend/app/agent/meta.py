"""Session metadata extraction (Phase 3 Task 3): privacy by design.

PRIVACY_ALLOW_LIST — exactly what may leave the sensor in an ingest message:
  agent_id, protocol, five_tuple (or hashed endpoints, see below),
  client/server host (optionally hashed/truncated), ports, is_starttls,
  start_ts/end_ts, tls_version, cipher, cipher_strength, pfs flag,
  cert subject/issuer CN + SAN count (NOT full chains/keys),
  rule finding summaries (rule_id/severity/title only), risk score band.

NEVER included: plaintext_segment, tls_segment (raw handshake bytes),
raw_refs, mail content, full certificates, keys, passwords.

Address handling (configurable):
  mode "full"     — IPs/hosts as observed (default; LAN sensors).
  mode "hashed"   — SHA-256 hex of each host (stable joins, no addresses).
  mode "truncated"— IP network part only (e.g. 10.0.0.0/24 -> "10.0.0.0").
"""
from __future__ import annotations

import hashlib
import ipaddress

PRIVACY_ALLOW_LIST = (
    "agent_id protocol five_tuple client_host server_host client_port "
    "server_port is_starttls start_ts end_ts tls_version cipher "
    "cipher_strength pfs_supported cert_cn cert_issuer san_count "
    "finding_ids max_severity risk_band"
)

_FORBIDDEN_MARKERS = (
    b"Subject:", b"MAIL FROM", b"RCPT TO", b"EHLO", b"STARTTLS",
)


def redact_host(host: str, mode: str, prefix_bits: int = 24) -> str:
    if mode == "hashed":
        return hashlib.sha256(host.encode()).hexdigest()[:32]
    if mode == "truncated":
        try:
            ip = ipaddress.ip_address(host)
            net = ipaddress.ip_network(f"{host}/{prefix_bits}", strict=False)
            return str(net.network_address)
        except ValueError:
            parts = host.split(".")
            return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "redacted"
    return host


def risk_band(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def session_to_metadata(sess, analysis=None, agent_id: str = "",
                        addr_mode: str = "full") -> dict:
    """Build the allow-listed metadata dict for one reassembled session.

    `sess` is a parsing Session; `analysis` an optional SessionAnalysis
    (adds TLS facts + finding summaries, still no payload bytes).
    """
    proto = sess.protocol.value if hasattr(sess.protocol, "value") else str(sess.protocol)
    tls_version = getattr(analysis, "negotiated_version_name", None) if analysis else None
    if tls_version is None and analysis is not None:
        tls_version = getattr(analysis, "tls_version", None)
    cipher = getattr(analysis, "cipher", None) if analysis else None
    findings = list(getattr(analysis, "findings", None) or [])
    cert_cns = []
    cert_issuer = ""
    if analysis is not None:
        for c in (getattr(analysis, "certs", None) or []):
            if getattr(c, "subject_cn", ""):
                cert_cns.append(c.subject_cn)
            if not cert_issuer and getattr(c, "issuer_cn", ""):
                cert_issuer = c.issuer_cn
    san_count = 0
    if analysis is not None and getattr(analysis, "certs", None):
        try:
            san_count = len(getattr(analysis.certs[0], "subject_alt_names", None) or [])
        except Exception:
            san_count = 0
    client = redact_host(getattr(sess, "client_ip", ""), addr_mode)
    server = redact_host(getattr(sess, "server_ip", ""), addr_mode)
    five = f"{client}:{sess.client_port}-{server}:{sess.server_port}"
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = max((f.severity for f in findings),
                  key=lambda s: sev_order.get(s, 0), default="none")
    return {
        "agent_id": agent_id,
        "protocol": proto,
        "five_tuple": five,
        "client_host": client,
        "server_host": server,
        "client_port": sess.client_port,
        "server_port": sess.server_port,
        "is_starttls": bool(getattr(sess, "is_starttls", False)),
        "start_ts": float(getattr(sess, "start_ts", 0.0) or 0.0),
        "end_ts": float(getattr(sess, "end_ts", 0.0) or 0.0),
        "tls_version": tls_version,
        "cipher": cipher,
        "cipher_strength": getattr(analysis, "cipher_strength", None) if analysis else None,
        "pfs_supported": bool(getattr(getattr(analysis, "cipher_meta", None), "pfs", False)),
        "cert_cn": cert_cns[0] if cert_cns else None,
        "cert_issuer": cert_issuer or None,
        "san_count": san_count,
        "finding_ids": [f.rule_id for f in findings],
        "max_severity": max_sev,
        "risk_band": risk_band(None),
    }
