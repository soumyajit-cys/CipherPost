import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
import ipaddress


def _build_name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CipherPost Lab"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])


def make_root_ca(cn: str = "CipherPost Root CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = _build_name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_leaf(
    root_cert, root_key, cn: str = "mail.cipherpost.test",
    key_size: int = 2048, key_type: str = "rsa", sig_hash: str = "sha256",
    days_valid: int = 825, not_before_offset_days: int = 0,
):
    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP384R1())
        public_key = key.public_key()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = key.public_key()

    hash_alg = getattr(hashes, sig_hash.upper())()

    cert = (
        x509.CertificateBuilder()
        .subject_name(_build_name(cn))
        .issuer_name(root_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=not_before_offset_days))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(root_key, hash_alg)
    )
    return cert, key


def make_self_signed(cn: str = "mail.cipherpost.test", key_size: int = 2048, days_valid: int = 825):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = _build_name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_untrusted_chain_cn(cn: str = "mail.other-org.test"):
    return make_self_signed(cn, days_valid=825)


def cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)
