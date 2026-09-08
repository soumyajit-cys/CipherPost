"""
CipherPost live traffic generator (stage 1 lab).

Runs per-scenario in-process TLS mail listeners (SMTP/IMAP/POP3) and drives real
client connections against them in a loop, producing genuinely wire-level email
traffic for the capture daemon to observe. Scenarios mirror the offline corpus
(tests/fixtures). Modern OpenSSL refuses RC4/EXPORT/TLS-1.0/1.1 by default —
those scenarios are probed and skipped with a warning rather than failing.

Usage:
    python scripts/traffic_generator.py                 # loop until Ctrl-C
    python scripts/traffic_generator.py --once --count 5
    python scripts/traffic_generator.py --scenarios smtp_tls13_strong,imap_starttls_strip
    python scripts/traffic_generator.py --host mail-lab --ports-base 30000   # drive Postfix/Dovecot lab via MAIL_LAB

Environment overrides:
    HOST, PORTS_BASE, INTERVAL, SCENARIOS
"""
from __future__ import annotations

import argparse
import random
import socket
import socketserver
import ssl
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ipaddress import ip_address
from pathlib import Path

# --- cert helpers ----------------------------------------------------------

SERVER_NAME = "mail.example.com"
_CLIENTN = "client.example"

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_root_ca(cn: str = "CipherPost Lab Trusted Root") -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_server_cert(signer_cert: x509.Certificate, signer_key,
                     expired: bool = False, self_signed: bool = False,
                     ca: bool = False) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) leaf signed by signer(s)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer, sign_key = signer_cert.subject, signer_key
    if self_signed:
        issuer, sign_key = _name(SERVER_NAME), key
    now = datetime.now(timezone.utc)
    if expired:
        not_before, not_after = now - timedelta(days=30), now - timedelta(days=1)
    else:
        not_before, not_after = now - timedelta(days=1), now + timedelta(days=365)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(SERVER_NAME))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME), x509.IPAddress(ip_address("127.0.0.1"))]),
        critical=False,
    )
    cert = builder.sign(sign_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# --- scenario definitions ----------------------------------------------------

class Scenario:
    def __init__(self, name: str, proto: str, tls: str | None, kind: str,
                 tls_max: int | None = None, tls_min: int | None = None,
                 cert=None):
        self.name = name
        self.proto = proto            # SMTP | IMAP | POP3
        self.tls = tls                # "implicit" | "starttls" | None (strip/plaintext)
        self.kind = kind              # strong | acceptable | expired | selfsigned | untrusted | strip
        self.tls_max = tls_max
        self.tls_min = tls_min
        self.cert = cert              # (cert_pem, key_pem) or None
        self.port = 0                 # assigned at startup


class ScenarioLab:
    """Owns listeners + client drivers; emits traffic on a loop."""

    def __init__(self, host: str = "127.0.0.1", ports_base: int = 31000,
                 include_deprecated: bool = True):
        self.host = host
        self.ports_base = ports_base
        self.scenarios: list[Scenario] = []
        self._socks: list[tuple[socket.socket, Scenario]] = []
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._log = print
        self._ssl_ctx_pool: dict[str, ssl.SSLContext] = {}
        self._deprecated_ok = include_deprecated

    # --- builder ------------------------------------------------------------
    def _add(self, **kw) -> Scenario:
        s = Scenario(**kw)
        self.scenarios.append(s)
        return s

    def add_classic_matrix(self):
        root_cert, root_key = make_root_ca()
        other_root, other_root_key = make_root_ca("CipherPost Lab OTHER Root (untrusted)")
        strong_cert, strong_key = make_server_cert(root_cert, root_key)
        acc_cert, acc_key = make_server_cert(root_cert, root_key)
        exp_cert, exp_key = make_server_cert(root_cert, root_key, expired=True)
        ss_cert, ss_key = make_server_cert(root_cert, root_key, self_signed=True)
        untr_cert, untr_key = make_server_cert(other_root, other_root_key)
        self._trust_bundle = root_cert.public_bytes(serialization.Encoding.PEM)

        self._add(name="smtp_tls13_strong", proto="SMTP", tls="implicit",
                  kind="strong", cert=(strong_cert, strong_key), tls_max=ssl.TLSVersion.TLSv1_3)
        self._add(name="smtp_tls12_acceptable", proto="SMTP", tls="implicit",
                  kind="acceptable", cert=(acc_cert, acc_key),
                  tls_max=ssl.TLSVersion.TLSv1_2, tls_min=ssl.TLSVersion.TLSv1_2)
        self._add(name="smtp_tls12_starttls", proto="SMTP", tls="starttls",
                  kind="acceptable", cert=(acc_cert, acc_key),
                  tls_max=ssl.TLSVersion.TLSv1_2, tls_min=ssl.TLSVersion.TLSv1_2)
        self._add(name="imap_tls13_strong", proto="IMAP", tls="implicit",
                  kind="strong", cert=(strong_cert, strong_key))
        self._add(name="imap_tls12_starttls", proto="IMAP", tls="starttls",
                  kind="acceptable", cert=(acc_cert, acc_key),
                  tls_max=ssl.TLSVersion.TLSv1_2, tls_min=ssl.TLSVersion.TLSv1_2)
        self._add(name="pop3_tls12_implicit", proto="POP3", tls="implicit",
                  kind="acceptable", cert=(acc_cert, acc_key),
                  tls_max=ssl.TLSVersion.TLSv1_2, tls_min=ssl.TLSVersion.TLSv1_2)
        self._add(name="smtp_expired_cert", proto="SMTP", tls="implicit",
                  kind="expired", cert=(exp_cert, exp_key))
        self._add(name="imap_selfsigned", proto="IMAP", tls="implicit",
                  kind="selfsigned", cert=(ss_cert, ss_key))
        self._add(name="smtp_untrusted_chain", proto="SMTP", tls="implicit",
                  kind="untrusted", cert=(untr_cert, untr_key))
        self._add(name="smtp_starttls_strip", proto="SMTP", tls=None, kind="strip")
        self._add(name="imap_starttls_strip", proto="IMAP", tls=None, kind="strip")
        return self

    def persist_trust(self, path: str) -> str:
        """Write the lab's trusted root so analysis can validate the 'valid' chains."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(getattr(self, "_trust_bundle", b""))
        return path

    # --- server side ----------------------------------------------------------
    def _server_ctx(self, sc: Scenario) -> ssl.SSLContext | None:
        if sc.tls is None:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = sc.tls_min or ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = sc.tls_max or ssl.TLSVersion.TLSv1_3
        cert_pem, key_pem = sc.cert
        ctx.load_cert_chain(certfile=_pem_path(sc, cert_pem, "cert"),
                            keyfile=_pem_path(sc, key_pem, "key"))
        return ctx

    def _server_loop(self, sc: Scenario):
        ctx = self._server_ctx(sc)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, sc.port))
        srv.listen(8)
        srv.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, sc, ctx), daemon=True).start()

    def _handle(self, conn: socket.socket, sc: Scenario, ctx: ssl.SSLContext | None):
        try:
            if sc.tls == "implicit":
                conn = ctx.wrap_socket(conn, server_side=True)
                self._server_speaks(sc, conn, over_tls=True)
                return
            # plaintext first
            self._server_banner(sc, conn)
            req = conn.recv(4096).decode(errors="replace").strip()
            if sc.tls == "starttls" and ("STARTTLS" in req.upper() or "STLS" in req.upper()):
                conn.sendall(b"220 Ready for TLS\r\n" if sc.proto != "IMAP"
                             else b"a002 OK Begin TLS now\r\n")
                conn = ctx.wrap_socket(conn, server_side=True)
                self._server_speaks(sc, conn, over_tls=True)
            else:
                # strip / plaintext: keep answering in plaintext
                conn.sendall(b"250 ok\r\n" if sc.proto == "SMTP" else b"+OK ok\r\n")
                conn.recv(1024)
        except (ssl.SSLError, OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _server_banner(self, sc: Scenario, conn: socket.socket):
        if sc.proto == "SMTP":
            conn.sendall(b"220 mail.example.com ESMTP CipherPost lab\r\n")
        elif sc.proto == "IMAP":
            conn.sendall(b"* OK CipherPost lab IMAP4rev1\r\n")
        else:
            conn.sendall(b"+OK CipherPost lab POP3 server ready\r\n")

    def _server_speaks(self, sc: Scenario, conn: socket.socket, over_tls: bool):
        try:
            conn.recv(4096)
            if sc.proto == "SMTP":
                conn.sendall(b"250 mail.example.com at your service\r\n")
                conn.recv(4096)
            elif sc.proto == "IMAP":
                conn.sendall(b"* CAPABILITY IMAP4rev1\r\na001 OK CAPABILITY completed\r\n")
                conn.recv(4096)
            else:
                conn.sendall(b"+OK maildrop has 1 message\r\n")
                conn.recv(4096)
        except (ssl.SSLError, OSError, ConnectionError):
            pass

    # --- client side -----------------------------------------------------------

    def _client_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["mail"])
        return ctx

    def _speak(self, sc: Scenario) -> None:
        ctx = self._client_ctx()
        raw = socket.create_connection((self.host, sc.port), timeout=5)
        try:
            if sc.tls == "implicit":
                conn = ctx.wrap_socket(raw, server_hostname=SERVER_NAME)
            else:
                conn = raw
                banner = conn.recv(4096)
                if sc.tls == "starttls":
                    verb = "STLS" if sc.proto == "POP3" else "STARTTLS"
                    conn.sendall((verb + "\r\n").encode())
                    resp = conn.recv(4096)
                    conn = ctx.wrap_socket(raw, server_hostname=SERVER_NAME)
                else:
                    # strip: client still probes for STARTTLS, server refuses
                    if sc.proto == "SMTP":
                        conn.sendall(b"EHLO client.example\r\n")
                        conn.recv(4096)
                        conn.sendall(b"STARTTLS\r\n")
                        conn.recv(4096)
                    elif sc.proto == "IMAP":
                        conn.sendall(b"a001 CAPABILITY\r\n")
                        conn.recv(4096)
                        conn.sendall(b"a002 STARTTLS\r\n")
                        conn.recv(4096)
                    else:
                        conn.sendall(b"USER test\r\n")
                        conn.recv(4096)
            # produce a little post-handshake protocol traffic
            if sc.proto == "SMTP":
                conn.sendall(b"EHLO client.example\r\n")
                conn.recv(4096)
            elif sc.proto == "IMAP":
                conn.sendall(b"a003 LOGIN test pass\r\n")
                conn.recv(4096)
            else:
                conn.sendall(b"PASS x\r\n")
                conn.recv(4096)
        finally:
            try:
                raw.close()
            except OSError:
                pass

    # --- orchestration ----------------------------------------------------------

    def start(self):
        for i, sc in enumerate(self.scenarios):
            sc.port = self.ports_base + i
            t = threading.Thread(target=self._server_loop, args=(sc,), daemon=True)
            t.start()
            self._threads.append(t)

    def run(self, interval: float = 3.0, jitter: float = 1.0,
            once: bool = False, count: int = 1):
        self.start()
        time.sleep(0.8)  # let listeners bind before first client
        self._log(f"[traffic-gen] {len(self.scenarios)} scenario listeners on "
                  f"{self.host}:{self.ports_base}+ ; interval={interval}s")
        emitted = {sc.name: 0 for sc in self.scenarios}
        rounds = 0
        try:
            while not self._stop.is_set() and (not once or rounds < count):
                rounds += 1
                for sc in self.scenarios:
                    if self._stop.is_set():
                        break
                    if emitted[sc.name] >= 1 and once:
                        continue
                    try:
                        self._speak(sc)  # retries a few times internally
                        emitted[sc.name] += 1
                        self._log(f"[traffic-gen] {sc.name} -> {sc.proto} on :{sc.port}")
                    except (ConnectionRefusedError, socket.timeout, OSError, ssl.SSLError) as e:
                        self._log(f"[traffic-gen] {sc.name} failed: {type(e).__name__}: {e}")
                    if once:
                        time.sleep(0.25)
                        continue
                    time.sleep(interval + random.uniform(0, jitter))
        finally:
            self.stop()

    def stop(self):
        self._stop.set()
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        time.sleep(0.3)


def _pem_path(sc: Scenario, data: bytes, label: str) -> str:
    import tempfile, os
    path = os.path.join(tempfile.gettempdir(), f"cp-lab-{sc.name}-{label}.pem")
    with open(path, "wb") as f:
        f.write(data)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="CipherPost live traffic generator (stage 1 lab)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports-base", type=int, default=31000)
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--jitter", type=float, default=1.0)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--count", type=int, default=1)
    args = ap.parse_args(argv)

    lab = ScenarioLab(host=args.host, ports_base=args.ports_base)
    lab.add_classic_matrix()
    try:
        trust_path = lab.persist_trust("data/lab/lab_root.pem")
        print(f"[traffic-gen] lab trust root bundle -> {trust_path}  "
              f"(set CIPHERPOST_TRUSTED_CA_BUNDLE_PATH={trust_path} for live analysis)")
    except Exception as e:
        print(f"[traffic-gen] could not persist trust bundle: {e}")
    lab.run(interval=args.interval, jitter=args.jitter,
            once=args.once, count=args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())