"""Live-run lab kit tests (Task 1): smoke-test logic + lab file consistency.

No container runtime or mail server required: TCP/API checks run against
local loopback sockets spun up in-process; lab file checks are static text
inspections of deploy/live-run/ contents.
"""
import importlib.util
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "deploy" / "live-run"

sys.path.insert(0, str(ROOT))


def _load_smoke():
    spec = importlib.util.spec_from_file_location(
        "lab_smoke_test", LAB / "smoke_test.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


smoke = _load_smoke()


# --- check_tcp against a real loopback listener -------------------------------

def test_check_tcp_passes_against_local_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert smoke.check_tcp("127.0.0.1", port, timeout=2) is True
    finally:
        srv.close()


def test_check_tcp_fails_on_closed_port():
    # Port 1 on loopback is not a lab service; bind-and-close to be certain.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert smoke.check_tcp("127.0.0.1", port, timeout=0.5) is False


# --- check_api against a real local HTTP server -------------------------------

class _OK(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *a):  # silence
        pass


class _ERR(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503)
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_check_api_passes_on_200():
    srv, url = _serve(_OK)
    try:
        assert smoke.check_api(url) is True
    finally:
        srv.shutdown()


def test_check_api_fails_on_503_and_on_unreachable():
    srv, url = _serve(_ERR)
    try:
        assert smoke.check_api(url) is False
    finally:
        srv.shutdown()
    # unreachable port (closed socket)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert smoke.check_api(f"http://127.0.0.1:{port}/api/v1/health") is False


# --- main(): result evaluation + failure messages -----------------------------

def test_main_all_pass(capsys):
    srv, url = _serve(_OK)
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
    port = listener.getsockname()[1]
    try:
        rc = smoke.main_with_overrides(
            host="127.0.0.1",
            ports=[(name, port) for name, _ in smoke.SERVICES],
            api_url=url)
        assert rc == 0
        out = capsys.readouterr().out
        assert out.count("[PASS]") == len(smoke.SERVICES) + 1
        assert "All smoke tests passed." in out
        assert "[FAIL]" not in out
    finally:
        listener.close()
        srv.shutdown()


def test_main_failure_counts_and_reports(capsys):
    # Closed port -> FAIL for every service; unreachable API -> FAIL.
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    rc = smoke.main_with_overrides(
        host="127.0.0.1",
        ports=[(name, closed) for name, _ in smoke.SERVICES],
        api_url=f"http://127.0.0.1:{closed}/api/v1/health")
    assert rc == 1
    out = capsys.readouterr().out
    assert out.count("[FAIL]") == len(smoke.SERVICES) + 1
    assert "check(s) FAILED." in out


# --- lab file consistency (static, no runtime) --------------------------------

def test_profiles_define_expected_tls_settings():
    expectations = {
        "modern": {"TLS_PROFILE_DIR": "modern", "TLS_LEVEL": "modern",
                   "SSL_CERT_PATH": "/certs/good.crt"},
        "legacy-tolerant": {"TLS_PROFILE_DIR": "legacy-tolerant",
                            "TLS_LEVEL": "intermediate",
                            "SSL_CERT_PATH": "/certs/good.crt"},
        "deliberately-broken": {"TLS_PROFILE_DIR": "deliberately-broken",
                                "TLS_LEVEL": "intermediate",
                                "SSL_CERT_PATH": "/certs/expired.crt"},
    }
    for profile, exp in expectations.items():
        env = {}
        for line in (LAB / "profiles" / f"{profile}.env").read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
        for k, v in exp.items():
            assert env.get(k) == v, f"{profile}.env: {k}={env.get(k)!r}, expected {v!r}"


def test_profile_overrides_match_expectations():
    broken = (LAB / "config" / "deliberately-broken" / "postfix-main.cf").read_text()
    assert "smtpd_tls_auth_only = no" in broken, "plaintext AUTH must be enabled"
    assert "smtpd_tls_ciphers = export" in broken, "weak ciphers must be allowed"
    legacy = (LAB / "config" / "legacy-tolerant" / "postfix-main.cf").read_text()
    assert "!SSLv3" in legacy, "TLS 1.0/1.1 must remain allowed (only SSLv2/v3 excluded)"
    modern = (LAB / "config" / "modern" / "postfix-main.cf").read_text()
    assert "smtpd_tls_protocols" not in modern, "modern profile must not relax protocols"


def test_compose_binds_only_loopback_and_uses_dms_image():
    compose = (LAB / "docker-compose.yml").read_text()
    import re
    published = re.findall(r'-\s*"127\.0\.0\.1:\d+:\d+"', compose)
    assert len(published) >= 7, "all mail+api ports must bind to 127.0.0.1"
    assert not re.search(r'-\s*"\d+:\d+"', compose), "no port may bind to all interfaces"
    assert "ghcr.io/docker-mailserver/docker-mailserver" in compose
    assert "SSL_TYPE=manual" in compose and "SSL_CERT_PATH" in compose


def test_lab_certs_output_names_match_profile_paths():
    """scripts/lab_certs.sh must produce the cert files the profiles reference."""
    script = (ROOT / "scripts" / "lab_certs.sh").read_text()
    for name in ("ca.crt", "good.crt", "good.key", "expired.crt", "expired.key"):
        assert name in script, f"lab_certs.sh does not generate {name}"
    # the compose mounts deploy/live-run/certs at /certs
    compose = (LAB / "docker-compose.yml").read_text()
    assert "./certs:/certs:ro" in compose
