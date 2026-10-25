# Baseline for the live-run / pilot kit task (2026-10-25)

Branch: `live-run-kit` (from `main` @ 78010de).
Environment: Linux (Fedora), Python 3.13.12 venv, Node 20.x, Docker 29
(daemon reachable), local Redis 7 (system service on localhost:6379),
local OpenSSL 3.x. No Postgres needed for the fast suite (SQLite/aiosqlite).

## Environment fixes needed to reproduce (recorded, not code changes)

- `pip install -r backend/requirements.txt -r backend/requirements.test.txt`
  does NOT install `pytest`/`pytest-cov`/`aiosqlite`; installed into the venv
  for the run (test-only deps; `hypothesis` pins nothing here).
- `CIPHERPOST_REDIS_URL=redis://localhost:6379/0` — default points at the
  compose hostname `redis`, which does not resolve on a dev box; ingest tests
  (`test_phase3_tenancy`) need a reachable Redis.
- `CIPHERPOST_TRUSTED_CA_BUNDLE_PATH=tests/fixtures/trusted_root.pem` —
  the default `None` falls back to the system CA bundle; the CLI golden test
  (`test_scan_exit_codes_and_golden_json`) expects the repo test CA.

Both env vars were exported for the run below. They are recorded here so the
owner can reproduce; a follow-up commit should set them in
`backend/tests/conftest.py` so the suite is self-contained.

## Commands and results

| Check | Command | Result |
|---|---|---|
| Fast tests | `PYTHONPATH=backend/. python -m pytest backend/tests -q -m "not slow"` | **223 passed, 11 deselected** (27.3 s) |
| Corpus eval | `PYTHONPATH=backend/. python -m app.parsing.eval_rules tests/fixtures` | 45 findings, 0 FP / 0 FN, P=1.00 R=1.00 (synthetic corpus) |
| ML eval | `PYTHONPATH=backend/. python -m app.ml.eval_ml tests/fixtures` | f1 1.0 / 1.0 (16 synthetic sessions — smoke only) |
| Real eval | `PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json` | 28 lab captures, 94 sessions, 0 FP / 0 FN (lab set) |
| OpenAPI gate | `PYTHONPATH=backend python scripts/check_openapi_break.py` | no breaking changes (80 paths) |
| Claims gate | `python scripts/check_claims.py` | OK (35 markdown files scanned) |
| Frontend | `npm ci && npm run build` (frontend/) | tsc clean, bundle built |

## Notes

- One `CryptographyDeprecationWarning` (negative serial) is emitted while
  parsing `tests/fixtures/trusted_root.pem` with cryptography 50.0.1 —
  warning only, validation unaffected. Pre-existing.
- Docker daemon IS present but not accessible from this session
  (`docker pull` → permission denied on `/var/run/docker.sock`), so the
  live-run lab can only be validated with `docker compose config`
  (static checks). Running the lab containers is **NOT-VERIFIED**.
- No production, live-run, or pilot claim is made anywhere in this file.
