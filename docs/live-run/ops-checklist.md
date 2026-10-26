# Ops checklist — unattended live run (daily / weekly / end-of-run)

For the owner running CipherPost unattended on a small VPS. Every "doctor"
line below means `cipherpost doctor --backup-dir /backups/cipherpost`
(local-only). Items that can be automated are covered by doctor; items that
need a human are marked manual. This checklist contains no results.

## Daily (5 minutes)

- [ ] `cipherpost doctor` — expect zero FAIL. Investigate any FAIL the same
      day (S1/S2 per `docs/live-run/triage.md`).
- [ ] `python scripts/live_report.py --start <yesterday> --end <today> --out
      <reports-dir>/YYYY-MM-DD` — confirm exit code and read FLAGS. A
      `capture-stop-suspected` or `coverage-gap` flag means the capture was
      blind at some point: treat as S1 until explained.
- [ ] Disk: doctor `disk-capture` line PASS (guard floor 2 GB) **and** glance
      at `df -h /` — the guard only protects raw captures, not the OS.
- [ ] Daily log filled (`docs/live-run/daily-log-template.md`).

## Weekly (15 minutes)

- [ ] Restore drill (must be done at least once before the run starts):
      ```bash
      # backup is taken nightly by cron (example below); verify + restore:
      ls -lt /backups/cipherpost/cipherpost-*.dump | head -3
      bash scripts/restore_postgres.sh --yes /backups/cipherpost/cipherpost-<NEWEST>.dump
      # CI runs the same backup → wipe → restore path (restore-check job);
      # the command above is the tested one — do not invent an ad-hoc psql flow.
      ```
- [ ] Cron/systemd timer actually fired (doctor `backups` PASS = newest dump
      < 26 h old; FAIL = backup job broken — fix before trusting the run).
- [ ] Clock: doctor `clock` PASS (NTP synchronized). Drift invalidates cert
      validity checks and report bucketing.
- [ ] Own TLS: doctor `own-tls-cert` not FAIL. If it warns (< 14 days),
      renew now — an expired API cert silently breaks agents/dashboards
      mid-run. Set `CIPHERPOST_OWN_TLS_CERT_PATH` so this check is possible.
- [ ] Data dirs growth: doctor `data-dirs` — WARN means uploads/reports/raw
      dirs are growing beyond ~2 GB; check rotation/retention settings.
- [ ] Labels: label the week's suspected false positives via the feedback
      flow (after `docs/live-run/triage.md` confirmation steps) and export
      provenance monthly with `scripts/export_labels.py`.
- [ ] Suppressions: review expiring-soon suppressions
      (`GET /api/v1/suppressions/expiring-soon`).

## Automation coverage (what doctor checks)

| Checklist item | Automated by doctor? | Check name |
|---|---|---|
| Disk floor for raw captures | yes (plus in-path guard in `RollingRawStore` that stops writes below 2 GB and logs `DISK GUARD`) | `disk-capture` |
| Memory pressure | yes (`MemAvailable` < 512 MB FAIL) | `memory` |
| Clock drift / NTP | yes | `clock` |
| CipherPost's own TLS expiry | yes (`CIPHERPOST_OWN_TLS_CERT_PATH`; FAIL ≤ 3 days, WARN < 14 days) | `own-tls-cert` |
| Backup freshness | yes (no dump / > 52 h FAIL; > 26 h WARN) | `backups` |
| DB reachable + size | yes (> 10 GB WARN — bloat/retention review) | `db` |
| Redis reachable + DLQ depth | yes (DLQ > 0 WARN → runbook Dead-letter) | `redis` |
| Log rotation | compose `x-logging` defaults (50 MB × 5 per container) + journald rate limits; size of data dirs via `data-dirs` | `data-dirs` |
| Engine imports / python version | yes | `engine-imports`, `python` |
| Captures actually seeing traffic | **manual** (live-report flags are the detector) | — |
| Findings quality / labels | **manual** (feedback flow) | — |

## Backup schedule example (cron)

```cron
# /etc/cron.d/cipherpost-backup — nightly 02:17, keeps 14 dumps (script default)
17 2 * * * postgres bash /opt/CipherPost/scripts/backup_postgres.sh /backups/cipherpost
# weekly integrity check (doctor fails loudly if dumps stop)
23 3 * * 1 root /opt/CipherPost/.venv/bin/cipherpost doctor --backup-dir /backups/cipherpost >> /var/log/cipherpost-doctor.log 2>&1
```

Rotate `/backups/cipherpost` off-host if the VPS is single-node: a backup on
the same disk as the database does not survive disk loss.

## End-of-run (the day the 30 days complete)

- [ ] Run `scripts/live_report.py` for the full range; save JSON+MD with the
      run records.
- [ ] Walk `docs/live-run/exit-criteria.md` fill-in checklist item by item.
- [ ] Export labels with provenance (`scripts/export_labels.py`); confirm the
      lab test set (`tests/real/`) was never modified during the run.
- [ ] Stop the capture cleanly; note final raw-capture size and confirm the
      rolling window purged old segments.
- [ ] Decide retention: keep or delete per the authorization you operated
      under; deletion is documented in `docs/pilot/data-handling-summary.md`.
- [ ] Update `docs/v1-readiness.md` and `docs/known-issues.md` with facts and
      evidence links only; run `scripts/check_claims.py`.
