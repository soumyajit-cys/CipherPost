"""Pilot preflight tests (Task 5): simulated failures, no real network calls
beyond loopback sockets the tests own."""
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "pilot_preflight",
    Path(__file__).resolve().parents[2] / "scripts" / "pilot_preflight.py")
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)


def _statuses(results):
    return {name: status for name, status, _ in results}


def _fake_run(mapping):
    """mapping: cmd[0] -> (rc, out)"""
    def run(cmd):
        return mapping.get(cmd[0], (127, f"no-sim for {cmd[0]}"))
    return run


# --- individual checks with simulated failures --------------------------------

def test_container_runtime_fail_when_daemon_down():
    status, detail = pf.check_container_runtime(
        run=_fake_run({"docker": (1, "Cannot connect to the Docker daemon")}))
    assert status == "FAIL" and "unreachable" in detail


def test_container_runtime_fail_when_binary_missing(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda name: None)
    status, _ = pf.check_container_runtime()
    assert status == "FAIL"


def test_container_runtime_pass(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda name: "docker")
    status, _ = pf.check_container_runtime(run=_fake_run({"docker": (0, "27.0.3\n")}))
    assert status == "PASS"


def test_kubernetes_warn_when_no_cluster(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda name: "kubectl")
    status, _ = pf.check_kubernetes(run=_fake_run({"kubectl": (1, "connection refused")}))
    assert status == "WARN"  # k8s is optional for compose path


def test_ports_warn_when_busy():
    srv = __import__("socket").socket()
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    try:
        status, detail = pf.check_ports((port,), connect=pf._connect)
        assert status == "WARN" and str(port) in detail
    finally:
        srv.close()


def test_disk_fail_low_space():
    status, detail = pf.check_disk("/data", free_gb=lambda p: 1.0)
    assert status == "FAIL" and "1.0 GB" in detail
    status, _ = pf.check_disk("/data", free_gb=lambda p: None)
    assert status == "FAIL"
    status, _ = pf.check_disk("/data", free_gb=lambda p: 7.5)
    assert status == "WARN"          # below 2x minimum
    status, _ = pf.check_disk("/data", free_gb=lambda p: 20.0)
    assert status == "PASS"


def test_clock_warn_when_no_sync_tools():
    status, detail = pf.check_clock(run=_fake_run({}))
    assert status == "WARN" and "NTP" in detail


def test_clock_pass_chrony():
    status, _ = pf.check_clock(run=_fake_run(
        {"chronyc": (0, "System time : 0.0000001 seconds fast of NTP time")}))
    assert status == "PASS"


def test_capture_permissions_warn_without_cap(monkeypatch):
    def denied():
        return False, "Operation not permitted"
    status, detail = pf.check_capture_permissions(netraw=denied)
    assert status == "WARN" and "live capture" in detail


def test_dns_fail():
    status, detail = pf.check_dns(("localhost", "no-such-host.invalid"),
                                  resolve=lambda h: h == "localhost")
    assert status == "FAIL" and "no-such-host.invalid" in detail


def test_capture_path_fail_and_usage_error():
    status, _ = pf.check_capture_path("10.9.9.9:9999", connect=lambda h, p: False)
    assert status == "FAIL"
    status, detail = pf.check_capture_path("no-port-here", connect=lambda h, p: True)
    assert status == "FAIL" and "host:port" in detail


def test_post_install_fail_and_pass():
    status, _ = pf.check_post_install("http://x", fetch=lambda url: {"status": "down"})
    assert status == "FAIL"
    status, _ = pf.check_post_install("http://x", fetch=lambda url: {"status": "ok"})
    assert status == "PASS"
    def boom(url):
        raise OSError("refused")
    status, _ = pf.check_post_install("http://x", fetch=boom)
    assert status == "FAIL"


# --- driver-level behavior -----------------------------------------------------

def test_run_checks_swallows_check_exceptions():
    def broken_run(cmd):
        raise RuntimeError("simulated crash inside check")
    results = pf.run_checks(dns_hosts=(), run=broken_run)
    # every check produced a result (none raised out of the driver)
    assert all(isinstance(r, tuple) and len(r) == 3 for r in results)


def test_run_checks_flags_capture_target_and_post_install():
    results = pf.run_checks(
        dns_hosts=("localhost",), capture_target="127.0.0.1:1",
        post_install_url="http://127.0.0.1:59999",
        run=_fake_run({}),
        connect=lambda h, p: False,
        fetch=lambda url: (_ for _ in ()).throw(OSError("refused")))
    st = _statuses(results)
    assert st["capture-path"] == "FAIL" and st["post-install-api"] == "FAIL"
    assert st["os/arch"] in ("PASS", "WARN")


def test_cli_exit_code_1_on_fail(capsys, monkeypatch, tmp_path):
    rc = pf.main(["--dns-hosts", "no-such-host.invalid", "--disk-path", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1 and "[FAIL]" in out and "nothing is sent anywhere" in out
