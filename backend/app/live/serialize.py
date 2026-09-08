"""
Session serialization for the Redis stream bus.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from app.parsing.reassembly import Session, Protocol

_SESSION_ATTRS = (
    "closed_by", "raw_refs", "tracked_bytes", "tls_version", "cipher",
    "cipher_iana", "client_hello", "server_hello", "certs", "chain_result",
)


def session_to_payload(sess: Session) -> bytes:
    d: dict[str, Any] = {
        "protocol": sess.protocol.value,
        "five_tuple": sess.five_tuple,
        "client_ip": sess.client_ip, "server_ip": sess.server_ip,
        "client_port": sess.client_port, "server_port": sess.server_port,
        "is_starttls": sess.is_starttls,
        "transition_offset": sess.transition_offset,
        "plaintext_segment": base64.b64encode(sess.plaintext_segment).decode(),
        "plaintext_server_segment": base64.b64encode(sess.plaintext_server_segment).decode(),
        "tls_segment": base64.b64encode(sess.tls_segment).decode(),
        "tls_server_segment": base64.b64encode(sess.tls_server_segment).decode(),
        "start_ts": sess.start_ts, "end_ts": sess.end_ts,
        "port_based": sess.port_based,
        "closed_by": getattr(sess, "closed_by", "unknown"),
        "tracked_bytes": getattr(sess, "tracked_bytes", 0),
        "raw_refs": [list(r) for r in (getattr(sess, "raw_refs", None) or [])],
    }
    return json.dumps(d).encode()


def session_from_payload(raw: bytes | dict) -> Session:
    if isinstance(raw, bytes):
        raw = raw.decode()
    d = json.loads(raw) if isinstance(raw, str) else raw
    sess = Session(
        protocol=Protocol(d["protocol"]),
        five_tuple=d["five_tuple"],
        client_ip=d["client_ip"], server_ip=d["server_ip"],
        client_port=d["client_port"], server_port=d["server_port"],
        is_starttls=d.get("is_starttls", False),
        transition_offset=d.get("transition_offset"),
        plaintext_segment=base64.b64decode(d.get("plaintext_segment", "") or ""),
        plaintext_server_segment=base64.b64decode(d.get("plaintext_server_segment", "") or ""),
        tls_segment=base64.b64decode(d.get("tls_segment", "") or ""),
        tls_server_segment=base64.b64decode(d.get("tls_server_segment", "") or ""),
        start_ts=d.get("start_ts", 0.0),
        end_ts=d.get("end_ts", 0.0),
        port_based=d.get("port_based", False),
    )
    sess.closed_by = d.get("closed_by", "unknown")
    sess.tracked_bytes = d.get("tracked_bytes", 0)
    sess.raw_refs = [tuple(r) for r in (d.get("raw_refs") or [])]
    return sess


def serialize_dict(d: dict) -> bytes:
    return json.dumps(d).encode()