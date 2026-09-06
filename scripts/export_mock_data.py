"""
Export real pipeline output to frontend mock fixtures.

Runs the actual analysis pipeline (reassembly → TLS parsing → rules → ML →
SHAP) over the labeled corpus and writes a JSON file at
frontend/src/api/mock/data.json shaped exactly like the frontend's API
contract, so the dashboard renders authentic data without a backend.

Usage:
    PYTHONPATH=backend/. .venv/bin/python scripts/export_mock_data.py
"""
from __future__ import annotations

import json
import os
import sys
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.parsing.reassembly import reconstruct_sessions
from app.parsing.analysis import analyze_pcap
from app.parsing.handshake import version_name, lookup_cipher
from app.parsing.tls_records import parse_tls_records
from app.parsing.certificates import CertAnalysis
from app.parsing.rules import max_severity
from app.ml.ml_engine import SessionScorer

FIXTURES = "tests/fixtures"
OUT = "frontend/src/api/mock/data.json"

TLS_CT_NAMES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
HS_MSG_NAMES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 15: "ClientKeyExchange", 4: "NewSessionTicket"}


def fmt_ts(dt: datetime.datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def cert_to_dict(c: CertAnalysis) -> dict:
    return {
        "subject": c.subject_cn,
        "issuer": c.issuer_cn,
        "notBefore": fmt_ts(c.not_before),
        "notAfter": fmt_ts(c.not_after),
        "daysValid": c.days_valid,
        "daysRemaining": c.days_remaining,
        "pubkeyAlg": c.pubkey_alg,
        "pubkeyBits": c.pubkey_bits,
        "signatureAlg": c.signature_alg,
        "selfSigned": c.is_self_signed,
        "isCa": c.is_ca,
        "weakSignature": c.weak_signature,
        "shortKey": c.short_key,
        "expired": c.expired,
        "notYetValid": c.not_yet_valid,
        "serial": c.serial,
        "sans": c.subject_alt_names,
        "chainResult": c.chain_result,
    }


def build_timeline(client_bytes: bytes, server_bytes: bytes,
                   plaintext_client: bytes, plaintext_server: bytes,
                   tls_client: bytes, tls_server: bytes,
                   transition_offset: int | None) -> list[dict]:
    """Build a human timeline of SMTP/IMAP/POP3 + TLS events."""
    events: list[dict] = []

    def add(offset: int, direction: str, etype: str, summary: str, raw: str):
        events.append({"offset": offset, "direction": direction,
                       "type": etype, "summary": summary, "raw": raw})

    def line_events(seg: bytes, direction: str):
        off = 0
        for rawline in seg.split(b"\r\n") if b"\r\n" in seg else seg.split(b"\n"):
            if not rawline:
                off += 2
                continue
            line = rawline.decode(errors="replace")
            upper = line.upper()
            etype = "plaintext"
            if upper.startswith(("220 ", "250 ", "334 ", "235 ", "OK", "AUTH", "DOVE", "ESMTP", "IMAP4", "+OK", "-ERR")):
                etype = "server-plaintext" if direction == "client" and False else "plaintext-server"
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                etype = "client-command"
            summary = line.strip()[:72]
            add(off, direction, etype, summary or "(empty line)", line)
            off += len(rawline) + 2

    if plaintext_client:
        line_events(plaintext_client, "client")
    if plaintext_server:
        line_events(plaintext_server, "server")

    if transition_offset is not None:
        add(transition_offset, "client", "starttls",
            "STARTTLS transition → TLS handshake begins here", f"offset={transition_offset}")

    for seg, direction in ((tls_client, "client"), (tls_server, "server")):
        try:
            recs = parse_tls_records(seg)
        except Exception:
            recs = []
        off = 0
        for rec in recs:
            ct_name = TLS_CT_NAMES.get(rec.content_type, f"0x{rec.content_type:02x}")
            summary = ct_name
            if rec.content_type == 22:
                # handshake
                buf = rec.payload
                pos = 0
                parts = []
                while pos + 4 <= len(buf):
                    mtype = buf[pos]
                    mlen = int.from_bytes(buf[pos+1:pos+4], "big")
                    parts.append(HS_MSG_NAMES.get(mtype, f"Handshake({mtype})"))
                    pos += 4 + mlen
                summary = ", ".join(parts) if parts else f"{ct_name}({len(buf)}B)"
            add(off, direction, "tls",
                summary, f"content_type={ct_name} version=0x{rec.version:04x} len={len(rec.payload)}")
            off += 5 + len(rec.payload)
    return events


def run():
    with open(os.path.join(FIXTURES, "corpus_index.json")) as f:
        corpus = json.load(f)["files"]

    trust = os.path.join(FIXTURES, "trusted_root.pem")
    all_analyses = []
    per_file: list[tuple] = []  # (ent, analyses, sessions_by_tuple)
    for ent in corpus:
        path = os.path.join(FIXTURES, f"{ent['name']}.pcap")
        analyses = analyze_pcap(path, trust_store=trust)
        sessions = reconstruct_sessions(path)
        all_analyses.extend(analyses)
        per_file.append((ent, analyses, sessions))

    scorer = SessionScorer(trust_store=trust)
    scorer.train(all_analyses)

    base_ts = datetime.datetime(2026, 9, 1, 10, 0, 0)
    analyses_out = []
    for i, (ent, analyses, sessions) in enumerate(per_file):
        score_results = [scorer.score(sa) for sa in analyses]
        by_tuple = {s.five_tuple_full: s for s in sessions}

        session_dicts = []
        finding_dicts = []
        kid = 0
        for si, (sa, sr) in enumerate(zip(analyses, score_results)):
            sess = by_tuple.get(sa.five_tuple)
            sid = f"{ent['name']}-s{si}"
            timeline = []
            if sess is not None:
                timeline = build_timeline(
                    sess.tls_segment + sess.plaintext_segment,
                    sess.tls_server_segment + sess.plaintext_server_segment,
                    sess.plaintext_segment, sess.plaintext_server_segment,
                    sess.tls_segment, sess.tls_server_segment,
                    sess.transition_offset,
                )
                cls = sa.client_hello
                ch = None
                if cls is not None:
                    ch = {
                        "sni": cls.sni,
                        "alpn": cls.alpn,
                        "offeredVersions": [version_name(v) for v in cls.offered_versions] or [version_name(cls.legacy_version)],
                        "cipherSuites": [f"0x{cs:04x}" for cs in cls.cipher_suites[:12]],
                        "supportedGroups": cls.supported_groups,
                    }
            sev = max_severity(sa.findings) or "none"
            session_dicts.append({
                "id": sid,
                "protocol": sa.protocol,
                "fiveTuple": sa.five_tuple,
                "srcIp": sess.client_ip if sess else "",
                "dstIp": sess.server_ip if sess else "",
                "srcPort": sess.client_port if sess else 0,
                "dstPort": sess.server_port if sess else 0,
                "isStarttls": sa.is_starttls,
                "transitionOffset": sess.transition_offset if sess else None,
                "tlsVersion": version_name(sa.tls_version),
                "cipher": sa.cipher,
                "cipherIana": f"0x{sa.cipher_iana:04x}" if sa.cipher_iana else None,
                "cipherStrength": round(sa.cipher_strength, 3) if sa.cipher_strength is not None else None,
                "cipherKind": sa.cipher_meta.kind if sa.cipher_meta else None,
                "pfsSupported": sa.cipher_meta.pfs if sa.cipher_meta else None,
                "certChainValid": sa.chain_result == "ok",
                "chainResult": sa.chain_result,
                "chainError": sa.chain_error,
                "riskScore": sr.risk.posture_score,
                "isAnomaly": bool(sr.anomaly.is_anomaly),
                "maxSeverity": sev,
                "findingCount": len(sa.findings),
                "clientHello": ch,
                "certChain": [cert_to_dict(c) for c in sa.certs],
                "timeline": timeline,
                "shap": [
                    {"feature": c.feature, "value": c.value, "impact": c.impact, "method": "score"}
                    for c in sr.shap_contributions
                ],
                "ruleMlAgreement": sr.rule_ml_agreement,
            })
            for fi, f in enumerate(sa.findings):
                finding_dicts.append({
                    "id": kid, "sessionId": sid, "ruleId": f.rule_id,
                    "ruleName": f.rule_name, "severity": f.severity,
                    "title": f.title, "description": f.description,
                    "reference": f.reference, "kind": f.kind,
                    "evidence": dict(f.evidence or {}),
                    "session": {"fiveTuple": sa.five_tuple, "protocol": sa.protocol},
                })
                kid += 1

        ts = base_ts + datetime.timedelta(minutes=11 * i, seconds=17 * i)
        fleet_score = round(sum(sr.risk.posture_score for sr in score_results) / max(1, len(score_results)))
        sev_dist = {}
        for sd in session_dicts:
            sev_dist[sd["maxSeverity"]] = sev_dist.get(sd["maxSeverity"], 0) + 1
        max_sev = max(sd["maxSeverity"] for sd in session_dicts) if session_dicts else None
        sev_rank = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        max_sev = max((sd["maxSeverity"] for sd in session_dicts), key=lambda s: sev_rank.get(s, 0)) if session_dicts else None

        finding_dicts.sort(key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x["severity"], 0), reverse=True)

        analyses_out.append({
            "id": ent["name"],
            "filename": f"{ent['name']}.pcap",
            "status": "completed",
            "progress": 1.0,
            "fileSize": os.path.getsize(os.path.join(FIXTURES, f"{ent['name']}.pcap")),
            "createdAt": ts.isoformat(),
            "completedAt": (ts + datetime.timedelta(seconds=9)).isoformat(),
            "postureScore": fleet_score,
            "findingsCount": len(finding_dicts),
            "sessionsCount": len(session_dicts),
            "maxSeverity": max_sev,
            "gotoLabel": ent.get("label", ent["name"]),
            "summaries": [
                {k: sd[k] for k in ("id", "protocol", "fiveTuple", "isStarttls", "tlsVersion",
                                    "cipher", "cipherStrength", "pfsSupported", "certChainValid",
                                    "riskScore", "isAnomaly", "maxSeverity", "findingCount")}
                for sd in session_dicts
            ],
            "sessions": session_dicts,
            "findings": finding_dicts,
            "fleet": {
                "totalSessions": len(session_dicts),
                "fleetScore": fleet_score,
                "anomalyCount": sum(1 for sd in session_dicts if sd["isAnomaly"]),
                "severityDistribution": sev_dist,
                "sessions": [
                    {"fiveTuple": sd["fiveTuple"], "protocol": sd["protocol"],
                     "riskScore": sd["riskScore"], "isAnomaly": sd["isAnomaly"],
                     "maxSeverity": sd["maxSeverity"], "tlsVersion": sd["tlsVersion"]}
                    for sd in session_dicts
                ],
            },
        })

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump({"analyses": analyses_out}, f, indent=1, default=str)
    total_findings = sum(a["findingsCount"] for a in analyses_out)
    total_sessions = sum(a["sessionsCount"] for a in analyses_out)
    print(f"Wrote {OUT}: {len(analyses_out)} analyses, {total_sessions} sessions, {total_findings} findings")


if __name__ == "__main__":
    run()