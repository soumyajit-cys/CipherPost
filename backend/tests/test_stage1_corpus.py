"""Stage 1 tests: labeled test corpus integrity."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.parsing.generate_corpus import define_corpus
from app.parsing.cert_utils import (
    make_root_ca, issue_leaf, make_self_signed, cert_to_pem,
)


def test_corpus_definition_covers_scenarios():
    corpus = define_corpus()
    protocols = {s.protocol for s in corpus}
    assert {"SMTP", "IMAP", "POP3"} <= protocols
    modes = {s.cert_mode for s in corpus}
    assert {"valid", "self-signed", "expired", "untrusted", "weak-sig", "short-key"} <= modes
    # both STARTTLS and implicit TLS present
    assert any(s.use_starttls for s in corpus)
    assert any(not s.use_starttls and s.port in (465, 993, 995) for s in corpus)
    # adversarial stripping samples
    assert any("strip" in s.name for s in corpus)


def test_cert_generation(tmp_path):
    root, rk = make_root_ca()
    leaf, _ = issue_leaf(root, rk, cn="mail.test")
    pem = cert_to_pem(leaf)
    assert b"BEGIN CERTIFICATE" in pem
    ss, _ = make_self_signed()
    assert b"BEGIN CERTIFICATE" in cert_to_pem(ss)


def test_fixture_files_and_pcap_readable():
    fixtures = Path("tests/fixtures")
    if not fixtures.exists():
        return  # generated at build time
    pcaps = sorted(fixtures.glob("*.pcap"))
    jfiles = sorted(fixtures.glob("*.json"))
    assert len(pcaps) == len(jfiles) - 1  # corpus_index.json extra
    from scapy.all import rdpcap
    for p in pcaps[:3]:
        pkts = rdpcap(str(p))
        assert len(pkts) > 0


def test_ground_truth_hash_and_labels():
    idx = Path("tests/fixtures/corpus_index.json")
    if not idx.exists():
        return
    data = json.loads(idx.read_text())
    assert data["sessions"] == len(data["files"])
    for ent in data["files"]:
        pcap = Path("tests/fixtures") / f"{ent['name']}.pcap"
        import hashlib
        h = hashlib.sha256(pcap.read_bytes()).hexdigest()
        assert h == ent["file_hash"]