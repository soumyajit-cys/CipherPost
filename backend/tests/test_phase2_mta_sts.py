"""Phase 2 Task 5: MTA-STS/DANE with local fake DNS + HTTPS (no internet)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import base64
import socket
import threading

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset


class FakeDNS:
    """Minimal UDP DNS server for .test zones (MX/TXT/TLSA/DNSKEY)."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self.zones: dict[tuple[str, str], list] = {}
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def add(self, name: str, rdtype: str, rdata_text: str, ttl: int = 60):
        rr = dns.rrset.from_text(name.rstrip(".") + ".", ttl, "IN", rdtype, rdata_text)
        self.zones.setdefault((name.lower().rstrip("."), rdtype.upper()), []).append(rr)

    def add_rrset(self, name: str, rrset):
        self.zones.setdefault((name.lower().rstrip("."), "ANY"), []).append(rrset)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                q = dns.message.from_wire(data)
                resp = dns.message.make_response(q)
                if q.question:
                    qn = q.question[0]
                    name = qn.name.to_text().rstrip(".").lower()
                    rtype = dns.rdatatype.to_text(qn.rdtype)
                    rrs = self.zones.get((name, rtype), []) + self.zones.get((name, "ANY"), [])
                    if rrs:
                        for rr in rrs:
                            resp.answer.append(rr)
                    else:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                self.sock.sendto(resp.to_wire(), addr)
            except Exception:
                pass


def _use_fake_dns(fake: FakeDNS):
    from app.core import config as cfg
    cfg.settings.DNS_RESOLVER = "127.0.0.1"  # port overridden below
    return cfg


def _patch_resolver_port(monkeypatch, fake: FakeDNS):
    """Point _resolver() at the fake server (dnspython has no port override)."""
    import app.proactive.mta_sts as m

    orig = m._resolver

    def _fake_resolver():
        r = orig()
        r.nameservers = ["127.0.0.1"]
        r.port = fake.port
        return r

    monkeypatch.setattr(m, "_resolver", _fake_resolver)


def test_no_mx_is_dns_error(monkeypatch):
    fake = FakeDNS().start()
    try:
        _patch_resolver_port(monkeypatch, fake)
        import app.proactive.mta_sts as m
        out = m.check_domain("nomx.test")
        assert out["status"] == "dns-error", out
        assert out["mta_sts"]["error"] is not None
    finally:
        fake.stop()


def test_no_txt_is_not_published(monkeypatch):
    fake = FakeDNS().start()
    fake.add("mx1.plain.test", "A", "93.184.216.34")
    fake.add("plain.test", "MX", "10 mx1.plain.test.")
    try:
        _patch_resolver_port(monkeypatch, fake)
        import app.proactive.mta_sts as m
        out = m.check_domain("plain.test")
        assert out["mta_sts"]["mode"] is None
        assert out["dane"]["tlsa_records"].get("mx1.plain.test", {}).get("dnssec") in (
            "not-published", "unknown")
    finally:
        fake.stop()


def test_unsigned_tlsa_is_insecure_never_dane(monkeypatch):
    fake = FakeDNS().start()
    fake.add("mx1.unsigned.test", "A", "93.184.216.34")
    fake.add("unsigned.test", "MX", "10 mx1.unsigned.test.")
    fake.add("_25._tcp.mx1.unsigned.test", "TLSA",
             "3 1 1 8a9a70596b7a04efa01acc0d13f14147444d1b9b7f39a0c3f6a5c96381a87e")
    try:
        _patch_resolver_port(monkeypatch, fake)
        import app.proactive.mta_sts as m
        res = m._fetch_tlsa("mx1.unsigned.test")
        assert res["dnssec"] == "insecure", res
        assert len(res["records"]) == 1
        # evaluate_session must NOT emit DANE findings for insecure data
        found = m.evaluate_session("unsigned.test", {
            "used_tls": True, "mx_host": "mx1.unsigned.test",
            "cert_der": b"\x00" * 32})
        assert not [f for f in found if f["rule_id"] == "dane-tlsa-mismatch"]
    finally:
        fake.stop()


def test_ssrf_guards():
    import app.proactive.mta_sts as m
    import pytest
    with pytest.raises(ValueError):
        m._assert_public_https_target("127.0.0.1")
    with pytest.raises(ValueError):
        m._assert_public_https_target("localhost")
    assert m._safe_redirect("https://mta-sts.a.test/.well-known/mta-sts.txt",
                            "http://evil.test/x") is None


def test_policy_parsing_and_enforce_plaintext_mismatch(monkeypatch):
    import app.proactive.mta_sts as m
    # Parsing: bypass network, feed a policy body through the parser path.
    assert m._MTA_STS_TXT_RE.search("v=STSv1; id=20240101T000000;")
    # Mismatch logic with stubbed posture (no network).
    monkeypatch.setattr(m, "check_domain", lambda d, refresh=False: {
        "domain": d, "status": "ok",
        "mta_sts": {"mode": "enforce"}, "dane": {"tlsa_records": {}}})
    found = m.evaluate_session("enforced.test", {"used_tls": False})
    assert found and found[0]["rule_id"] == "mta-sts-enforce-plaintext"
    assert m.evaluate_session("enforced.test", {"used_tls": True,
                                                "cert_ok": True}) == []
    assert m.mismatch_for_session("enforced.test", False) is not None
    assert m.mismatch_for_session("enforced.test", True) is None


def test_tlsa_matching_vectors():
    import hashlib
    import app.proactive.mta_sts as m
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "mx.t.test")])
    cert = (_x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    # usage 3 (DANE-EE), selector 1 (SPKI), type 1 (SHA2-256)
    rec = {"usage": 3, "selector": 1, "mtype": 1,
           "cert": hashlib.sha256(spki).hexdigest()}
    assert m.tlsa_matches(rec, der) is True
    bad = dict(rec, cert="00" * 32)
    assert m.tlsa_matches(bad, der) is False
    # usage 0/1 (PKIX) are out of scope -> never match (no guessing)
    assert m.tlsa_matches({"usage": 0, "selector": 0, "mtype": 0,
                           "cert": der.hex()}, der) is False
