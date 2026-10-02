"""Phase 4 Task 1: TLS 1.3 hello parsing, visibility, and probe guards.

All fixtures below are SYNTHETIC (hand-built byte strings, file names and
docs say so). No real captures, labels, or fingerprints are invented.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _u16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def _ext(etype: int, body: bytes) -> bytes:
    return _u16(etype) + _u16(len(body)) + body


def _sni_ext(name: bytes) -> bytes:
    entry = b"\x00" + _u16(len(name)) + name
    return _ext(0, _u16(len(entry)) + entry)


def _groups_ext(groups: list[int]) -> bytes:
    body = b"".join(_u16(g) for g in groups)
    return _ext(10, _u16(len(body)) + body)


def _versions_ext(versions: list[int]) -> bytes:
    body = b"".join(_u16(v) for v in versions)
    return _ext(43, bytes([len(body)]) + body)


def _keyshare_ext(groups: list[int]) -> bytes:
    entries = b"".join(_u16(g) + _u16(32) + b"\x55" * 32 for g in groups)
    return _ext(51, _u16(len(entries)) + entries)


def _sigalgs_ext(algs: list[int]) -> bytes:
    body = b"".join(_u16(a) for a in algs)
    return _ext(13, _u16(len(body)) + body)


def _client_hello_bytes(exts: bytes, ciphers=(0x1301, 0x1302), grease: bool = False) -> bytes:
    suites = list(ciphers)
    if grease:
        suites = [0x0A0A] + suites + [0x1A1A]
    cs = b"".join(_u16(c) for c in suites)
    body = (_u16(0x0303) + b"\x11" * 32 + bytes([0])
            + _u16(len(cs)) + cs + bytes([1, 0])
            + _u16(len(exts)) + exts)
    return body


def _server_hello_bytes(random: bytes, cipher: int = 0x1301, exts: bytes = b"") -> bytes:
    return (_u16(0x0303) + random + bytes([0]) + _u16(cipher)
            + bytes([0]) + _u16(len(exts)) + exts)


def test_client_hello_fields_and_grease_stripped():
    from app.parsing.handshake import parse_client_hello, strip_grease, is_grease
    exts = (_sni_ext(b"mail.example.com") + _groups_ext([29, 0x0A0A, 256])
            + _versions_ext([0x0304, 0x0303]) + _keyshare_ext([29])
            + _sigalgs_ext([0x0403, 0x0804]) + _ext(45, b"\x01\x00")
            + _ext(42, b"") + _ext(0xFE0D, b"\x00"))
    info = parse_client_hello(_client_hello_bytes(exts, grease=True))
    assert info.sni == "mail.example.com"
    assert info.offered_versions == [0x0304, 0x0303]
    assert info.key_share_groups == [29]
    assert info.sig_algs == [0x0403, 0x0804]
    assert info.psk_kex_modes == [0]
    assert info.early_data_offered is True
    assert info.ech_outer is True
    assert info.compression == [0]
    assert info.grease_count >= 3  # cipher + group + (counted) occurrences
    assert 0x0A0A not in strip_grease(info.cipher_suites + info.supported_groups)
    assert is_grease(0x0A0A) and is_grease(0xFAFA) and not is_grease(0x1301)


def test_server_selected_group_hrr_and_sentinel():
    from app.parsing.handshake import (
        parse_server_hello, HRR_RANDOM, DOWNGRAD_SENTINEL_TLS12)
    # selected group via key_share ext
    info = parse_server_hello(_server_hello_bytes(
        b"\x22" * 32, exts=_ext(51, _u16(29)) + _ext(43, _u16(0x0304))))
    assert info.selected_group == 29
    assert info.negotiated_version == 0x0304
    assert not info.is_hrr and info.downgrade_sentinel is None
    # HelloRetryRequest
    hrr = parse_server_hello(_server_hello_bytes(HRR_RANDOM))
    assert hrr.is_hrr is True
    # downgrade sentinel (TLS 1.2 marker)
    sentinel = parse_server_hello(_server_hello_bytes(b"\x33" * 24 + DOWNGRAD_SENTINEL_TLS12))
    assert sentinel.downgrade_sentinel == "tls12"


def test_truncated_and_malformed_never_raise():
    from app.parsing.handshake import parse_client_hello, parse_server_hello
    from app.parsing.tls_records import TlsParseError
    import pytest
    with pytest.raises(TlsParseError):
        parse_client_hello(b"\x03")
    with pytest.raises(TlsParseError):
        parse_server_hello(b"\x03\x03" + b"\x00" * 5)
    # truncated extensions return partial info instead of raising
    info = parse_client_hello(_u16(0x0303) + b"\x11" * 32 + bytes([0])
                              + _u16(2) + _u16(0x1301) + bytes([1, 0]))
    assert info.cipher_suites == [0x1301]


def test_not_observable_flows_to_session():
    from app.parsing.analysis import analyze_pcap
    for name in ("smtp_tls13_strong", "imap_tls13_strong"):
        sas = analyze_pcap(f"tests/fixtures/{name}.pcap",
                           trust_store="tests/fixtures/trusted_root.pem")
        assert sas, name
        sa = sas[0]
        assert sa.visibility.get("tls13") is True
        assert sa.visibility["cert_chain"] in ("observed", "not_observable_tls13")
        assert sa.findings == []  # strong fixtures stay clean


def test_probe_private_blocked_by_default():
    from app.proactive import probe as _p
    import pytest
    with pytest.raises(ValueError, match="refusing"):
        _p.probe_host("127.0.0.1", 25)
    with pytest.raises(ValueError, match="refusing"):
        _p.probe_host("10.0.0.5", 25)


def _local_tls_server(certfile, keyfile, ready):
    import socket
    import ssl
    import threading
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    ready.append(srv.getsockname()[1])

    def _serve():
        try:
            conn, _ = srv.accept()
            tls = ctx.wrap_socket(conn, server_side=True)
            try:
                tls.recv(1024)
                tls.sendall(b"220 test\r\n")
            finally:
                try:
                    tls.close()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            srv.close()

    threading.Thread(target=_serve, daemon=True).start()


def test_probe_local_implicit_tls_with_allow_private(tmp_path):
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    from app.proactive import probe as _p
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "probe.test")])
    cert = (_x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()))
    ready: list = []
    _local_tls_server(str(cf), str(kf), ready)
    import time
    for _ in range(100):
        if ready:
            break
        time.sleep(0.05)
    out = _p.probe_host("127.0.0.1", ready[0], allow_private=True, starttls=False)
    assert out["cert_count"] >= 1
    assert out["certs"][0]["subject_cn"] == "probe.test"
    assert out["tls_version"] in ("TLSv1.2", "TLSv1.3")
    import pytest
    with pytest.raises(ValueError, match="rate limited"):
        _p.probe_host("127.0.0.1", ready[0], allow_private=True, starttls=False)
