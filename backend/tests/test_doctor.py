"""Doctor tests (Task 6): failure injection — low disk, expired cert, clock
skew, memory pressure, backup staleness. No real services required except
loopback-free helpers."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core import doctor
from app.live.retention import RollingRawStore

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


def _make_cert(days: float, path):
    """Self-signed cert whose not_valid_after is `days` from NOW
    (negative = already expired; not_valid_before sits before both)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cipherpost.local")])
    not_after = NOW + timedelta(days=days)
    not_before = min(NOW, not_after) - timedelta(days=30)
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(not_before)
         .not_valid_after(not_after))
    cert = b.sign(key, hashes.SHA256())
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


# --- failure injection: low disk ------------------------------------------------

def test_disk_fail_and_warn():
    status, detail = doctor.check_disk_space("/capture", free_gb=lambda p: 0.5)
    assert status == doctor.FAIL and "0.50 GB" in detail
    status, _ = doctor.check_disk_space("/capture", free_gb=lambda p: 3.0)
    assert status == doctor.WARN
    status, _ = doctor.check_disk_space("/capture", free_gb=lambda p: 9.0)
    assert status == doctor.PASS
    status, _ = doctor.check_disk_space("/capture", free_gb=lambda p: None)
    assert status == doctor.FAIL


# --- failure injection: expired / expiring own TLS cert --------------------------

def test_own_tls_cert_expired_fails(tmp_path):
    cert = _make_cert(-5, tmp_path / "expired.pem")   # expired 5 days before NOW
    status, detail = doctor.check_own_tls_cert(str(cert), now=NOW)
    assert status == doctor.FAIL and "EXPIRED" in detail


def test_own_tls_cert_expiring_soon(tmp_path):
    cert = _make_cert(7.5, tmp_path / "soon.pem")
    status, detail = doctor.check_own_tls_cert(str(cert), now=NOW)
    assert status == doctor.WARN and "7.5 days" in detail
    cert3 = _make_cert(2, tmp_path / "days3.pem")
    status, _ = doctor.check_own_tls_cert(str(cert3), now=NOW)
    assert status == doctor.FAIL
    certok = _make_cert(30, tmp_path / "ok.pem")
    status, _ = doctor.check_own_tls_cert(str(certok), now=NOW)
    assert status == doctor.PASS


def test_own_tls_cert_unset_warns_and_unreadable_fails(tmp_path):
    status, detail = doctor.check_own_tls_cert(None, now=NOW)
    assert status == doctor.WARN and "OWN_TLS_CERT_PATH" in detail
    status, _ = doctor.check_own_tls_cert(str(tmp_path / "nope.pem"), now=NOW)
    assert status == doctor.FAIL


# --- failure injection: clock skew (no sync tooling) ------------------------------

def test_clock_fail_when_unverifiable():
    status, _ = doctor.check_clock(run=lambda cmd: (127, "not found"))
    assert status == doctor.FAIL


def test_clock_fail_when_not_synchronized():
    status, _ = doctor.check_clock(
        run=lambda cmd: (0, "NTPSynchronized=no") if "timedatectl" in cmd else (127, ""))
    assert status == doctor.FAIL


def test_clock_pass_chrony():
    status, _ = doctor.check_clock(run=lambda cmd: (
        0, "System time : 0.0000001 seconds fast of NTP time"))
    assert status == doctor.PASS


# --- failure injection: memory ----------------------------------------------------

def test_memory_fail_on_low_available():
    status, detail = doctor.check_memory(meminfo=lambda: {"MemAvailable": 200_000})
    assert status == doctor.FAIL and "195 MB" in detail
    status, _ = doctor.check_memory(meminfo=lambda: {"MemAvailable": 4_000_000})
    assert status == doctor.PASS
    status, _ = doctor.check_memory(meminfo=lambda: (_ for _ in ()).throw(OSError()))
    assert status == doctor.WARN


# --- failure injection: backups ----------------------------------------------------

def test_backups_fail_when_dir_missing_or_empty(tmp_path):
    status, _ = doctor.check_backups(str(tmp_path / "nope"), now=NOW)
    assert status == doctor.FAIL
    status, detail = doctor.check_backups(str(tmp_path), now=NOW)
    assert status == doctor.FAIL and "not being taken" in detail


def test_backups_warn_and_fail_on_staleness(tmp_path):
    import os
    fresh = tmp_path / "cipherpost-20261025.dump"
    fresh.write_bytes(b"x")
    ts = (NOW - timedelta(hours=5)).timestamp()
    os.utime(fresh, (ts, ts))  # 5h old
    status, _ = doctor.check_backups(str(tmp_path), now=NOW)
    assert status == doctor.PASS
    ts = (NOW - timedelta(hours=30)).timestamp()  # > 26h
    os.utime(fresh, (ts, ts))
    status, _ = doctor.check_backups(str(tmp_path), now=NOW)
    assert status == doctor.WARN
    ts = (NOW - timedelta(hours=72)).timestamp()  # > 52h
    os.utime(fresh, (ts, ts))
    status, detail = doctor.check_backups(str(tmp_path), now=NOW)
    assert status == doctor.FAIL and "failing" in detail


# --- disk guard (RollingRawStore) ---------------------------------------------------

def test_disk_guard_drops_then_recovers(tmp_path, monkeypatch):
    from app.live.retention import RollingRawStore, _disk_free_bytes
    state = {"free": 10 * 1024 ** 3}
    monkeypatch.setattr("app.live.retention._disk_free_bytes",
                        lambda p: state["free"])
    store = RollingRawStore(tmp_path, retention_seconds=3600,
                            disk_min_free_bytes=1 * 1024 ** 3)
    frame = b"\x00" * 32
    # below floor -> drops, returns None, counts
    state["free"] = 0
    dropped = [store.write(1.0, frame) for _ in range(3)]
    assert all(r is None for r in dropped)
    assert store._disk_guard_dropped == 3 and store._disk_guard_active
    # recovery -> writes succeed again, ref tuple returned
    state["free"] = 10 * 1024 ** 3
    ref = store.write(2.0, frame)
    assert ref is not None and store._disk_guard_active is False
    assert store._disk_guard_dropped == 3  # counter keeps history
    store.stop()


def test_disk_guard_real_low_disk_via_statvfs_stub(tmp_path, monkeypatch):
    """Simulate low disk without root: stub statvfs through the helper."""
    import app.live.retention as ret
    monkeypatch.setattr(ret, "_disk_free_bytes", lambda p: 100)  # 100 bytes free
    store = RollingRawStore(tmp_path, retention_seconds=3600,
                            disk_min_free_bytes=1024)
    assert store.write(1.0, b"x" * 8) is None
    assert store._disk_guard_dropped == 1
    store.stop()


# --- driver + render ---------------------------------------------------------------

def test_run_doctor_covers_ops_items(monkeypatch, tmp_path):
    """Every automatable ops-checklist item appears as a doctor check."""
    monkeypatch.setenv("CIPHERPOST_BACKUP_DIR", str(tmp_path))
    results = doctor.run_doctor(
        db_url="sqlite:///x", redis_url="redis://localhost:6399/0",
        raw_dir=str(tmp_path), run=lambda cmd: (127, "no"),
        free_gb=lambda p: 10.0,
        meminfo=lambda: {"MemAvailable": 8_000_000})
    names = {n for n, _, _ in results}
    assert {"python", "engine-imports", "db", "redis", "clock", "disk-capture",
            "memory", "own-tls-cert", "backups", "data-dirs"} <= names
    text, rc = doctor.render(results)
    assert rc in (0, 1) and "FAIL" in text


def test_doctor_cli_exit_codes(monkeypatch, capsys, tmp_path):
    from app import cli
    monkeypatch.setenv("CIPHERPOST_BACKUP_DIR", str(tmp_path))
    rc = cli.main(["doctor", "--raw-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert "cipherpost doctor" in out
    assert rc in (0, 1)
