"""
Stage 3: X.509 certificate analysis and chain-of-trust validation.

Uses `cryptography` for parsing and pyOpenSSL X509Store for path validation
against a configurable trusted root bundle (or the system store by default).

All DER input is untrusted: parse failures are trapped and surfaced as
findings, never as crashes.
"""
from __future__ import annotations

import os
import ssl
import datetime
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.exceptions import UnsupportedAlgorithm

try:
    from OpenSSL import crypto as ossl
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False


WEAK_SIGNATURE_ALGS = {"sha1", "md5"}


@dataclass
class CertAnalysis:
    subject_cn: str
    issuer_cn: str
    not_before: datetime.datetime | None
    not_after: datetime.datetime | None
    days_valid: float | None
    days_remaining: float | None
    pubkey_alg: str
    pubkey_bits: int | None
    signature_alg: str
    is_self_signed: bool
    is_ca: bool
    chain_result: str           # ok | untrusted | expired | not-yet-valid | invalid-sig | config-error
    chain_error: str = ""
    chain_trusted: bool = False
    serial: str = ""
    subject_alt_names: list[str] = field(default_factory=list)
    der: bytes = b""

    @property
    def expired(self) -> bool:
        if not self.not_after:
            return False
        return datetime.datetime.utcnow() > self.not_after

    @property
    def not_yet_valid(self) -> bool:
        if not self.not_before:
            return False
        return datetime.datetime.utcnow() < self.not_before

    @property
    def weak_signature(self) -> bool:
        sig = (self.signature_alg or "").split("_")[0].lower()
        return sig in WEAK_SIGNATURE_ALGS

    @property
    def short_key(self) -> bool:
        if self.pubkey_alg == "RSA" and self.pubkey_bits and self.pubkey_bits < 2048:
            return True
        if self.pubkey_alg == "DSA" and self.pubkey_bits and self.pubkey_bits < 2048:
            return True
        if self.pubkey_alg in ("EC", "ECDSA") and self.pubkey_bits and self.pubkey_bits < 224:
            return True
        return False


def _cn(name: x509.Name) -> str:
    try:
        return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        return "<oid missing>"


def _pubkey_info(pub) -> tuple[str, int | None]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return "Unknown", None


def analyze_certificate(der: bytes) -> CertAnalysis:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        return CertAnalysis(
            subject_cn="<unparseable>", issuer_cn="<unparseable>",
            not_before=None, not_after=None, days_valid=None, days_remaining=None,
            pubkey_alg="Unknown", pubkey_bits=None, signature_alg="unknown",
            is_self_signed=False, is_ca=False, chain_result="parse-error",
            chain_error=str(e)[:256], der=der,
        )
    now = datetime.datetime.utcnow()
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    not_before = not_before.replace(tzinfo=None)
    not_after = not_after.replace(tzinfo=None)
    try:
        sig = cert.signature_algorithm_oid._name or "unknown"
    except Exception:
        sig = "unknown"
    pub_alg, bits = _pubkey_info(cert.public_key())
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    except Exception:
        is_ca = False
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        sans = []
    serial = format(cert.serial_number, "x")
    return CertAnalysis(
        subject_cn=_cn(cert.subject),
        issuer_cn=_cn(cert.issuer),
        not_before=not_before,
        not_after=not_after,
        days_valid=(not_after - not_before).days,
        days_remaining=(not_after - now).days,
        pubkey_alg=pub_alg,
        pubkey_bits=bits,
        signature_alg=sig,
        is_self_signed=(_cn(cert.subject) == _cn(cert.issuer) and cert.subject == cert.issuer),
        is_ca=is_ca,
        chain_result="unknown",
        serial=serial,
        subject_alt_names=sans,
        der=der,
    )


def _load_trust_bundle(path: str | None) -> list["ossl.X509"] | None:
    """
    Load trust anchors. Returns list of X509 objects, or None to use system
    store. NB: pyOpenSSL X509Store does NOT load system trust by default, so
    we read the system bundle (SSL_CERT_FILE) when path is None.
    """
    if path is None:
        bundle = os.environ.get("SSL_CERT_FILE") or "/etc/ssl/certs/ca-certificates.crt"
    else:
        bundle = path
    certs = []
    try:
        with open(bundle, "rb") as f:
            data = f.read()
        from cryptography.hazmat.primitives.serialization import Encoding, load_pem_x509_certificates
        for c in load_pem_x509_certificates(data):
            certs.append(ossl.load_certificate(ossl.FILETYPE_ASN1, c.public_bytes(Encoding.DER)))
    except Exception:
        return None
    return certs


def validate_chain(der_certs: list[bytes], trust_path: str | None = None,
                   hostname: str | None = None) -> tuple[str, str]:
    """
    Validate the certificate chain against the configured trust store.

    Returns (result, detail). result in:
      ok, untrusted, expired, not-yet-valid, invalid-sig, hostname-mismatch,
      parse-error, config-error
    """
    if not HAS_OPENSSL:
        return "config-error", "pyOpenSSL not available"
    if not der_certs:
        return "parse-error", "empty chain"
    trust = _load_trust_bundle(trust_path)
    try:
        store = ossl.X509Store()
        added = 0
        if trust:
            for t in trust:
                store.add_cert(t)
                added += 1
        if not trust or added == 0:
            return "config-error", "no trust anchors could be loaded"
        chain = []
        for der in der_certs:
            chain.append(ossl.load_certificate(ossl.FILETYPE_ASN1, der))
        ctx = ossl.X509StoreContext(store, chain[0], chain=chain[1:])
        try:
            ctx.verify_certificate()
            result = "ok"
        except ossl.X509StoreContextError as e:
            code, detail = (e.args[0], str(e.args[1]) if len(e.args) > 1 else str(e))
            if "expired" in detail.lower():
                return "expired", detail
            if "not yet valid" in detail.lower():
                return "not-yet-valid", detail
            if "unable to get local issuer certificate" in detail.lower():
                return "untrusted", detail
            if "unable to get issuer certificate" in detail.lower():
                return "untrusted", detail
            if "self signed certificate" in detail.lower():
                return "untrusted", detail
            if "signature algorithm" in detail.lower():
                return "invalid-sig", detail
            if "signature" in detail.lower():
                return "invalid-sig", detail
            return "untrusted", f"{detail} (err code {code})"
    except Exception as e:
        return "config-error", str(e)[:256]
    if hostname:
        try:
            if not ctx.verify_certificate() is None:
                pass
        except Exception:
            pass
        # hostname check via ssl match_hostname
        first = chain[0]
        try:
            cert = x509.load_der_x509_certificate(der_certs[0])
            sans = []
            try:
                sans = list(cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            except Exception:
                pass
            if hostname not in sans:
                return "hostname-mismatch", f"{hostname} not in SANs"
        except Exception:
            return "parse-error", "could not check hostname"
    return result, "verified against trust store"