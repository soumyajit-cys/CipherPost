"""Per-mail-flow aggregation + regression detection (Phase 2 Task 6).

A flow is one (client_host, server_host, protocol, port) direction observed on
the wire. Each analyzed session updates its flow row (upsert); regression is
detected by comparing the new session against the flow's best-seen state:

- encrypted flow (all previous sessions TLS) now sees plaintext, or
- best-seen TLS version was 1.2/1.3 and the new session negotiates lower.

Regression findings flow into the normal alert pipeline (grouped by Task 2).
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

log = logging.getLogger("cipherpost.live.flows")

_VERSION_RANK = {"SSLv3": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}


def version_rank(v: str | None) -> int:
    return _VERSION_RANK.get((v or "").strip(), -1)


def flow_id(org_id: str | None, client: str, server: str,
            protocol: str, port: int) -> str:
    key = "|".join([org_id or "", client, server, protocol, str(port)])
    return "flow-" + hashlib.sha256(key.encode()).hexdigest()[:32]


def parse_five_tuple(five_tuple: str) -> tuple[str, str, int]:
    """Split 'c-ip:c-port-s-ip:s-port' into (client, server, server_port)."""
    try:
        left, right = five_tuple.split("-", 1)
        c_ip = left.rsplit(":", 1)[0]
        s_ip, s_port = right.rsplit(":", 1)
        return c_ip, s_ip, int(s_port)
    except Exception:
        return "", "", 0


def update_flow(db, org_id: str | None, sess_payload: dict,
                tls_version: str | None, cipher: str | None,
                encrypted: bool, seen_at=None,
                fingerprints: list[str] | None = None) -> tuple[object, dict | None]:
    """Upsert the flow row. Returns (flow_row, regression_finding|None).

    Never raises (retention of flow stats must not break session persistence).
    New fingerprints for established flows are recorded in
    flow.fingerprints and counted via the caller's gossip.
    """
    from app.models.entities import MailFlow
    try:
        five_tuple = sess_payload.get("five_tuple", "") or ""
        protocol = sess_payload.get("protocol", "") or ""
        client, server, port = parse_five_tuple(five_tuple)
        fid = flow_id(org_id, client, server, protocol, port)
        now = seen_at or datetime.now(timezone.utc)
        if getattr(now, "tzinfo", None) is None:
            now = now.replace(tzinfo=timezone.utc)
        flow = db.get(MailFlow, fid)
        regression = None
        if flow is None:
            flow = MailFlow(
                id=fid, org_id=org_id or "", client_host=client,
                server_host=server, protocol=protocol, port=port,
                total_sessions=0, encrypted_sessions=0, plaintext_sessions=0,
                versions={}, ciphers={}, best_version=tls_version,
                first_seen=now, last_seen=now)
            db.add(flow)
        else:
            regression = detect_regression(flow, tls_version, encrypted)
        flow.total_sessions = (flow.total_sessions or 0) + 1
        if encrypted:
            flow.encrypted_sessions = (flow.encrypted_sessions or 0) + 1
        else:
            flow.plaintext_sessions = (flow.plaintext_sessions or 0) + 1
        if tls_version:
            versions = dict(flow.versions or {})
            versions[tls_version] = versions.get(tls_version, 0) + 1
            flow.versions = versions
            if version_rank(tls_version) > version_rank(flow.best_version):
                flow.best_version = tls_version
        if cipher:
            ciphers = dict(flow.ciphers or {})
            ciphers[cipher] = ciphers.get(cipher, 0) + 1
            flow.ciphers = ciphers
        if flow.first_seen is None or now < _as_aware(flow.first_seen):
            flow.first_seen = now
        flow.last_seen = now
        new_fingerprints: list[str] = []
        if fingerprints:
            seen_fps = dict(flow.fingerprints or {})
            for fp in fingerprints:
                if not fp:
                    continue
                if fp in seen_fps:
                    seen_fps[fp] = seen_fps[fp] + 1 if isinstance(seen_fps[fp], int) else 1
                else:
                    seen_fps[fp] = 1
                    # "new fingerprint appeared": only meaningful with history.
                    if (flow.total_sessions or 0) > 3:
                        new_fingerprints.append(fp)
            flow.fingerprints = seen_fps
        # Transient (not a column): lets callers react without schema churn.
        flow.new_fingerprints = new_fingerprints
        return flow, regression
    except Exception as e:
        log.debug("flow update skipped: %s", e)
        return None, None


def _as_aware(dt):
    if dt is not None and getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def detect_regression(flow, tls_version: str | None, encrypted: bool) -> dict | None:
    """Compare a new session against stored best-seen state."""
    prev_total = flow.total_sessions or 0
    if prev_total < 3:
        return None  # need history before crying regression
    prev_best = flow.best_version
    if not encrypted and (flow.plaintext_sessions or 0) == 0:
        return {
            "rule_id": "transport-regression",
            "severity": "high",
            "title": (f"Flow {flow.client_host} -> {flow.server_host}:{flow.port} "
                      f"({flow.protocol}) sent plaintext after {prev_total} encrypted sessions"),
        }
    if tls_version and prev_best and version_rank(tls_version) < version_rank(prev_best):
        return {
            "rule_id": "transport-regression",
            "severity": "medium",
            "title": (f"Flow {flow.client_host} -> {flow.server_host}:{flow.port} "
                      f"({flow.protocol}) downgraded from {prev_best} to {tls_version}"),
        }
    return None
