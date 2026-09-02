"""Stage 3 tests: TLS handshake/cert parsing and the rules engine vs ground truth."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest

from app.parsing.analysis import analyze_pcap
from app.parsing.handshake import parse_client_hello, parse_server_hello
from app.parsing.certificates import analyze_certificate, validate_chain


FIXTURES = Path("tests/fixtures")


@pytest.fixture(scope="module")
def trust_store():
    p = FIXTURES / "trusted_root.pem"
    return str(p) if p.exists() else None


@pytest.fixture(scope="module")
def corpus():
    with open(FIXTURES / "corpus_index.json") as f:
        return json.load(f)["files"]


def test_strong_tls13_has_no_findings(trust_store):
    for name in ("smtp_tls13_strong", "imap_tls13_strong"):
        a = analyze_pcap(f"tests/fixtures/{name}.pcap", trust_store=trust_store)[0]
        assert a.negotiated_version_name == "TLS1.3"
        assert a.cipher is not None
        assert a.chain_result == "ok"
        assert a.findings == []


def test_tls10_flagged(trust_store):
    a = analyze_pcap("tests/fixtures/imap_tls10_weak.pcap", trust_store=trust_store)[0]
    rule_ids = {f.rule_id for f in a.findings}
    assert "tls-version-tls1-0" in rule_ids
    assert "rc4-cipher" in rule_ids


def test_export_and_ssl3_critical(trust_store):
    a = analyze_pcap("tests/fixtures/pop3_export_cipher.pcap", trust_store=trust_store)[0]
    sev = [f.severity for f in a.findings if f.rule_id == "export-grade-cipher"]
    assert sev == ["critical"]
    assert any(f.rule_id == "tls-version-sslv3" for f in a.findings)


def test_expired_and_selfsigned(trust_store):
    a = analyze_pcap("tests/fixtures/smtp_expired_cert.pcap", trust_store=trust_store)[0]
    assert any(f.rule_id == "expired-certificate" for f in a.findings)
    a2 = analyze_pcap("tests/fixtures/imap_selfsigned.pcap", trust_store=trust_store)[0]
    assert any(f.rule_id == "self-signed-certificate" for f in a2.findings)
    a3 = analyze_pcap("tests/fixtures/smtp_untrusted_chain.pcap", trust_store=trust_store)[0]
    assert any(f.rule_id == "untrusted-certificate-chain" for f in a3.findings)


def test_short_key_and_weak_sig(trust_store):
    a = analyze_pcap("tests/fixtures/smtp_short_key.pcap", trust_store=trust_store)[0]
    assert any(f.rule_id == "short-public-key" for f in a.findings)
    a2 = analyze_pcap("tests/fixtures/smtp_weak_sig.pcap", trust_store=trust_store)[0]
    assert any(f.rule_id == "weak-signature-algorithm" for f in a2.findings)


def test_starttls_stripping_detected(trust_store):
    a = analyze_pcap("tests/fixtures/smtp_starttls_strip.pcap", trust_store=trust_store)[0]
    rule_ids = {f.rule_id for f in a.findings}
    assert "starttls-strip-attempt" in rule_ids
    assert "plaintext-mail-protocol" in rule_ids


def test_full_corpus_perfect_match(trust_store, corpus):
    """The rules engine must reproduce ground truth exactly on the labeled corpus."""
    from collections import defaultdict
    bad = []
    for ent in corpus:
        pcap = f"tests/fixtures/{ent['name']}.pcap"
        a = analyze_pcap(pcap, trust_store=trust_store)[0]
        got = {f.rule_id for f in a.findings}
        expected = set(ent["expected_findings"])
        if got != expected:
            bad.append((ent["name"], sorted(expected), sorted(got)))
    assert bad == [], f"ground-truth mismatches: {bad}"


def test_client_hello_sni_and_sigalgs():
    from app.parsing.reassembly import reconstruct_sessions
    s = reconstruct_sessions("tests/fixtures/smtp_tls13_strong.pcap")[0]
    recs = s.tls_records
    from app.parsing.handshake import _handshake_body
    msgs = _handshake_body(recs)
    ch = parse_client_hello(msgs[1])
    assert ch.sni == "mail.cipherpost.test"
    assert 0x1302 in ch.cipher_suites  # TLS_AES_256_GCM_SHA384
    assert ch.supported_groups  # PFS group offered


def test_certificate_fields(trust_store):
    a = analyze_pcap("tests/fixtures/imap_selfsigned.pcap", trust_store=trust_store)[0]
    assert a.certs
    leaf = a.certs[0]
    assert leaf.subject_cn == "mail.cipherpost.test"
    assert leaf.pubkey_alg == "RSA"
    assert leaf.pubkey_bits == 2048
    assert leaf.is_self_signed is True