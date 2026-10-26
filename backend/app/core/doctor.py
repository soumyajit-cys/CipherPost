"""`cipherpost doctor` — installed-state checks for unattended operation.

Covers the failure modes that hurt a month-long run on a small VPS:
disk filling (captures, DB, logs), memory exhaustion, clock drift,
CipherPost's own TLS expiry, database size, backup freshness, and the
runtime health of DB/Redis. Every check degrades to WARN/FAIL with a
clear message instead of raising.

Importing this module must stay cheap (no fastapi/redis/sqlalchemy at
module scope — those are imported lazily inside checks, preserving the
cli.py offline-import rule). All I/O goes through injectable helpers so
tests simulate failures without a real stack.
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
MIN_DISK_GB = 2.0          # raw-capture filesystem floor (disk guard default)
MIN_MEM_MB = 512           # MemAvailable floor
BACKUP_MAX_AGE_H = 26.0    # nightly backup must exist within this window
CERT_WARN_DAYS = 14


def _free_gb(path: str) -> float | None:
    try:
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) / (1024 ** 3)
    except OSError:
        return None


def _run(cmd: list[str]) -> tuple[int, str]:
    import subprocess
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


# --- checks -------------------------------------------------------------------

def check_python() -> tuple[str, str]:
    v = os.sys.version_info
    if v >= (3, 11):
        return PASS, f"Python {v.major}.{v.minor}.{v.micro}"
    return FAIL, f"Python {v.major}.{v.minor} — 3.11+ required"


def check_engine_imports() -> tuple[str, str]:
    try:
        from app.parsing.analysis import analyze_session  # noqa: F401
        from app.parsing.certificates import validate_chain  # noqa: F401
        return PASS, "parsing engine imports"
    except Exception as e:
        return FAIL, f"engine import failed: {str(e)[:140]}"


def check_db(db_url: str | None = None) -> tuple[str, str]:
    if not db_url or db_url.startswith("sqlite"):
        return WARN, f"DB not checked (url={db_url or 'unset'}; sqlite is dev-only)"
    try:
        from sqlalchemy import create_engine, text
        eng = create_engine(db_url, connect_args={"connect_timeout": 3})
        try:
            with eng.connect() as c:
                c.execute(text("SELECT 1"))
                try:
                    size = c.execute(text(
                        "SELECT pg_database_size(current_database())")).scalar()
                    gb = (size or 0) / (1024 ** 3)
                    if gb > 10:
                        return WARN, f"DB reachable; size {gb:.1f} GB (>10 — check bloat/retention)"
                    return PASS, f"DB reachable; size {gb:.2f} GB"
                except Exception:
                    return PASS, "DB reachable (non-Postgres size query unavailable)"
        finally:
            eng.dispose()
    except Exception as e:
        return FAIL, f"DB unreachable: {str(e)[:140]}"


def check_redis(redis_url: str | None = None) -> tuple[str, str]:
    if not redis_url:
        return WARN, "Redis not checked (url unset)"
    try:
        import redis
        r = redis.Redis.from_url(redis_url, socket_connect_timeout=3, socket_timeout=3)
        r.ping()
        from app.core.config import settings as _s
        from app.live.streams import dlq_name
        dlq = r.xlen(dlq_name(_s.SESSION_STREAM))
        if dlq:
            return WARN, f"Redis reachable; dead-letter depth {dlq} (runbook: Dead-letter)"
        return PASS, "Redis reachable; DLQ empty"
    except Exception as e:
        return FAIL, f"Redis unreachable: {str(e)[:140]}"


def check_clock(run=None) -> tuple[str, str]:
    """Clock drift breaks certificate validity checks — confirm NTP."""
    run = run or _run
    rc, out = run(["chronyc", "tracking"])
    if rc == 0 and "System time" in out:
        line = [l for l in out.splitlines() if "System time" in l][0]
        return PASS, line.strip()
    rc, out = run(["timedatectl", "show", "--property=NTPSynchronized"])
    if rc == 0 and "yes" in out.lower():
        return PASS, "NTP synchronized (timedatectl)"
    return FAIL, ("NTP sync unverifiable (chrony/timedatectl missing or not synced). "
                  "Clock drift invalidates certificate expiry checks")


def check_disk_space(path: str, free_gb=None,
                     minimum: float = MIN_DISK_GB) -> tuple[str, str]:
    free_gb = free_gb or _free_gb
    free = free_gb(path)
    if free is None:
        return FAIL, f"cannot stat {path}"
    if free < minimum:
        return FAIL, f"only {free:.2f} GB free at {path} (<{minimum} GB guard floor)"
    if free < minimum * 2:
        return WARN, f"{free:.2f} GB free at {path} — capture storage may hit the guard soon"
    return PASS, f"{free:.2f} GB free at {path}"


def check_memory(meminfo=None, minimum: float = MIN_MEM_MB) -> tuple[str, str]:
    meminfo = meminfo or (lambda p="/proc/meminfo": {
        l.split(":")[0]: int(l.split()[1]) for l in open(p).read().splitlines()
        if ":" in l and l.split()[1].isdigit()})
    try:
        info = meminfo()
    except OSError:
        return WARN, "/proc/meminfo unreadable (non-Linux?) — memory not checked"
    avail = info.get("MemAvailable", 0) / 1024.0
    if avail < minimum:
        return FAIL, f"MemAvailable {avail:.0f} MB < {minimum:.0f} MB — OOM risk"
    return PASS, f"MemAvailable {avail:.0f} MB"


def check_own_tls_cert(path: str | None, now: datetime | None = None,
                       warn_days: int = CERT_WARN_DAYS) -> tuple[str, str]:
    """Self-expiry warning for CipherPost's own TLS cert (API/proxy)."""
    now = now or datetime.now(timezone.utc)
    if not path:
        return WARN, ("CIPHERPOST_OWN_TLS_CERT_PATH unset — CipherPost cannot watch "
                      "its own API TLS; configure it or verify the reverse-proxy cert "
                      "by other means")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID
        with open(path, "rb") as f:
            data = f.read()
        cert = x509.load_pem_x509_certificate(data)
        name = (cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                or [None])[0]
        cn = name.value if name is not None else "?"
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # older cryptography
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days = (not_after - now).total_seconds() / 86400.0
        if days <= 0:
            return FAIL, f"own TLS cert '{cn}' EXPIRED {-days:.1f} days ago ({path})"
        if days < 3:
            return FAIL, f"own TLS cert '{cn}' expires in {days:.1f} days ({path})"
        if days < warn_days:
            return WARN, f"own TLS cert '{cn}' expires in {days:.1f} days ({path})"
        return PASS, f"own TLS cert '{cn}' valid for {days:.0f} days"
    except Exception as e:
        return FAIL, f"own TLS cert unreadable at {path}: {str(e)[:120]}"


def check_backups(backup_dir: str | None, now: datetime | None = None,
                  max_age_h: float = BACKUP_MAX_AGE_H) -> tuple[str, str]:
    now = now or datetime.now(timezone.utc)
    if not backup_dir:
        return WARN, ("no backup dir configured (pass --backup-dir or set "
                      "CIPHERPOST_BACKUP_DIR) — nightly dumps cannot be verified")
    d = shutil.os.path.expanduser(backup_dir)
    if not os.path.isdir(d):
        return FAIL, f"backup dir missing: {d}"
    dumps = [f for f in os.listdir(d) if f.startswith("cipherpost-") and
             (f.endswith(".dump") or f.endswith(".dump.gz"))]
    if not dumps:
        return FAIL, f"no cipherpost-*.dump in {d} — backups are not being taken"
    newest = max(os.path.getmtime(os.path.join(d, f)) for f in dumps)
    age_h = (now.timestamp() - newest) / 3600.0
    if age_h > max_age_h * 2:
        return FAIL, f"newest backup is {age_h:.0f} h old (> {max_age_h * 2:.0f} h) — backup job failing"
    if age_h > max_age_h:
        return WARN, f"newest backup is {age_h:.0f} h old (nightly expected)"
    return PASS, f"newest backup {age_h:.1f} h old ({len(dumps)} dumps kept)"


def check_log_dirs(paths: list[str], max_gb: float = 2.0) -> tuple[str, str]:
    """Log/data growth: report the total size of writable data dirs."""
    total = 0
    missing = []
    for p in paths:
        if not os.path.isdir(p):
            missing.append(p)
            continue
        for root, _dirs, files in os.walk(p):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    gb = total / (1024 ** 3)
    detail = f"{gb:.2f} GB in {len(paths) - len(missing)} dir(s)"
    if missing:
        detail += f"; missing: {', '.join(missing)}"
    if gb > max_gb:
        return WARN, f"{detail} (> {max_gb} GB — check rotation/retention)"
    return PASS, detail


# --- driver -------------------------------------------------------------------

def run_doctor(db_url=None, redis_url=None, raw_dir=".", backup_dir=None,
               own_tls_cert=None, data_dirs=None, run=None, free_gb=None,
               meminfo=None, now=None) -> list[tuple[str, str, str]]:
    from app.core.config import settings as _s
    results = []

    def add(name, fn, *a, **kw):
        try:
            status, detail = fn(*a, **kw)
        except Exception as e:
            status, detail = WARN, f"check errored: {str(e)[:120]}"
        results.append((name, status, detail))

    add("python", check_python)
    add("engine-imports", check_engine_imports)
    add("db", check_db, db_url or _s.DATABASE_URL_SYNC)
    add("redis", check_redis, redis_url or _s.REDIS_URL)
    add("clock", check_clock, run)
    add("disk-capture", check_disk_space, str(raw_dir), free_gb)
    add("memory", check_memory, meminfo)
    add("own-tls-cert", check_own_tls_cert,
        own_tls_cert or getattr(_s, "OWN_TLS_CERT_PATH", None), now)
    add("backups", check_backups, backup_dir or os.environ.get("CIPHERPOST_BACKUP_DIR"), now)
    add("data-dirs", check_log_dirs, data_dirs or
        [str(_s.RAW_CAPTURE_DIR), str(_s.UPLOAD_DIR), str(_s.REPORTS_DIR)])
    return results


def render(results) -> tuple[str, int]:
    lines, n_fail = [], 0
    for name, status, detail in results:
        detail = " ".join(str(detail).split())  # collapse newlines from tracebacks
        lines.append(f"[{status:4}] {name:15} {detail}")
        if status == FAIL:
            n_fail += 1
    lines.append(f"{n_fail} FAIL, {sum(1 for _, s, _ in results if s == WARN)} WARN, "
                 f"{sum(1 for _, s, _ in results if s == PASS)} PASS")
    return "\n".join(lines), 1 if n_fail else 0
