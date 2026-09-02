"""
Stage 3 orchestrator: Session -> SessionAnalysis -> findings.

Combines reassembled Session with handshake parsing, certificate analysis,
and the rules engine. One entry point: analyze_session(session).
"""
from __future__ import annotations

from app.parsing.reassembly import Session, Protocol, IMPLICIT_TLS_PORTS
from app.parsing.handshake import (
    parse_client_hello, parse_server_hello, parse_certificate_message,
    _handshake_body, lookup_cipher, version_name, TlsParseError, TLS_VERSION_NAMES,
)
from app.parsing.certificates import analyze_certificate, validate_chain
from app.parsing.tls_records import parse_tls_records, TlsParseError as RecErr
from app.parsing import rules
from app.parsing.rules import SessionAnalysis, run_rules
from app.core.config import settings


def analyze_session(sess: Session, trust_store: str | None = None) -> SessionAnalysis:
    sa = SessionAnalysis(
        session_id=sess.five_tuple,
        protocol=sess.protocol.value if isinstance(sess.protocol, Protocol) else sess.protocol,
        five_tuple=sess.five_tuple_full,
        is_starttls=sess.is_starttls,
    )
    sa.is_implicit_tls_port = sess.server_port in IMPLICIT_TLS_PORTS
    sa.port = sess.server_port
    sa.saw_starttls_offer = (
        b"STARTTLS" in sess.plaintext_segment
        or b"STARTTLS" in sess.plaintext_server_segment
        or b"STLS" in sess.plaintext_segment
    )
    sa.expected_starttls = sa.saw_starttls_offer
    sa.started_tls = len(sess.tls_segment) > 0
    sa.tls_bytes = len(sess.tls_segment)
    sa.plaintext_bytes = len(sess.plaintext_segment)

    if trust_store is None:
        trust_store = settings.TRUSTED_CA_BUNDLE_PATH

    if not sa.started_tls:
        # Plaintext or stripped session — rules handle findings.
        run_rules(sa)
        return sa

    # Parse TLS records from the client stream
    try:
        records = parse_tls_records(sess.tls_segment)
    except RecErr:
        records = []

    if records:
        msgs = _handshake_body(records)
        if 1 in msgs:  # ClientHello
            try:
                sa.client_hello = parse_client_hello(msgs[1])
            except TlsParseError:
                sa.client_hello = None
        if 2 in msgs:  # ServerHello
            try:
                sa.server_hello = parse_server_hello(msgs[2])
            except TlsParseError:
                sa.server_hello = None
        if 11 in msgs:  # Certificate
            try:
                is_tls13 = sa.server_hello.negotiated_version == 0x0304 if sa.server_hello else False
                sa.certificate = parse_certificate_message(msgs[11], is_tls13=is_tls13)
            except TlsParseError:
                sa.certificate = None

    # Negotiated version & cipher
    if sa.server_hello is not None:
        nv = sa.server_hello.negotiated_version
        sa.tls_version = nv
        sa.negotiated_version_name = version_name(nv)
        sa.cipher_iana = sa.server_hello.cipher_suite
        if sa.cipher_iana:
            meta = lookup_cipher(sa.cipher_iana)
            if meta:
                sa.cipher_meta = meta
                sa.cipher = meta.name
                sa.cipher_strength = meta.strength
            else:
                sa.cipher = f"0x{sa.cipher_iana:04x}"
    elif sa.client_hello is not None:
        # No ServerHello: fall back to the client's top version offer
        if sa.client_hello.offered_versions:
            sa.tls_version = max(sa.client_hello.offered_versions)
        else:
            sa.tls_version = sa.client_hello.legacy_version
        sa.negotiated_version_name = version_name(sa.tls_version)

    # Certificates
    if sa.certificate and sa.certificate.raw_certs:
        sa.certs = [analyze_certificate(der) for der in sa.certificate.raw_certs]
        chain_result, chain_error = validate_chain(
            sa.certificate.raw_certs,
            trust_path=trust_store,
            hostname=sa.client_hello.sni if sa.client_hello else None,
        )
        sa.chain_result = chain_result
        sa.chain_error = chain_error
        for ca in sa.certs:
            ca.chain_result = sa.chain_result
    else:
        sa.chain_result = "no-cert"

    run_rules(sa)
    return sa


def analyze_pcap(pcap_path: str, trust_store: str | None = None) -> list[SessionAnalysis]:
    from app.parsing.reassembly import reconstruct_sessions
    sessions = reconstruct_sessions(pcap_path)
    return [analyze_session(s, trust_store) for s in sessions]