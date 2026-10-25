# Evidence: unattended-run ops safety (Task 6, 2026-10-25)

Branch `live-run-kit`. Tool versions: Python 3.13.12, cryptography 50.0.1.

## What ran

1. **`cipherpost doctor` on this host (real output)**:
   `PYTHONPATH=backend/. python -m app.cli doctor --raw-dir /tmp/opencode`
   → 6 PASS / 2 WARN / 2 FAIL — the FAILs are correct for a dev box
   (compose hostnames `db`/`redis` unresolvable outside the stack);
   clock NTP-synchronized (timedatectl), disk/memory PASS, own-TLS and
   backups WARN with actionable text (unset config). Multi-line traceback
   details collapse to one line in the render.

2. **Failure injection (backend/tests/test_doctor.py, 14 tests)**:
   - low disk (0.5/3/9 GB + unstat-able path) → FAIL/WARN/PASS/FAIL
   - expired own TLS cert (real PEM generated with cryptography,
     not_valid_after 5 days in the past) → FAIL "EXPIRED"; 2.5 days → FAIL;
     7.5 days → WARN; 30 days → PASS; unset path → WARN; unreadable → FAIL
   - clock skew: chrony absent + timedatectl `NTPSynchronized=no` → FAIL;
     synchronized → PASS
   - memory: MemAvailable 195 MB → FAIL; 3.9 GB → PASS; unreadable → WARN
   - backups: missing dir/empty dir → FAIL; 30 h old → WARN; 72 h → FAIL
   - **disk guard** (`RollingRawStore`): free-space stubbed below the 2 GB
     floor → `write()` returns None, frames counted
     (`_disk_guard_dropped`), error log once per window; recovery resumes
     writes automatically (stub + statvfs-level simulation)

3. **Regression**: full fast suite green after the guard change
   (276 passed, including all pre-existing retention/reassembly tests).

## What this changes in shipped behavior

- `RollingRawStore.write()` stops writing raw frames when free space on the
  capture filesystem drops below `CIPHERPOST_RAW_DISK_MIN_FREE_BYTES`
  (default 2 GB) and resumes automatically; drops are counted in memory
  gossip (`raw_dropped_disk_guard`) and logged as ERROR (rate-limited).
  This is the "stop capture storage before the disk fills" guard.
- `docker/docker-compose.yml` and `deploy/live-run/docker-compose.yml` set
  json-file log rotation defaults (50 MB × 5 files per container).
- `cipherpost doctor` (new CLI subcommand, `backend/app/core/doctor.py`)
  automates the checklist items listed in
  `docs/live-run/ops-checklist.md` (automation-coverage table).
- `CIPHERPOST_OWN_TLS_CERT_PATH` (new setting) lets doctor watch
  CipherPost's own TLS expiry.

## NOT-VERIFIED (with what is missing)

- **Real low-disk fill on a live capture**: the guard is verified via
  injected/statvfs-stubbed free-space values, not by filling a real disk
  during capture (would need a scratch filesystem; risky on this host).
- **Real expired API TLS in a running stack**: cert expiry logic verified
  against generated certs; a running nginx/API refusing an expired cert is
  upstream behavior, not exercised here.
- **journald/logrotate behavior on a real VPS**: compose json-file rotation
  is config-validated only; systemd-journald rate limits are documented,
  not exercised.
- **Backup freshness against a real cron**: verified via injected
  timestamps; the nightly cron example in ops-checklist is the operator's
  step (the backup/restore scripts themselves are CI-verified by the
  existing restore-check job).
