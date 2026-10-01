# Contributing to CipherPost

## Ground rules

- One focused commit per task with a clear message; never rewrite history or
  force-push to shared branches.
- Baseline first: `PYTHONPATH=backend/. python -m pytest backend/tests -q`
  must stay green after every change.
- Every behavior change needs a test that fails before and passes after.
  Failure-mode tests (crash, restart, outage) are required, not optional.
- Schema changes go through new Alembic migrations (upgrade **and**
  downgrade). Never edit an existing migration.
- Never claim something works unless you ran it; say exactly what you could
  not verify and why.
- Security-sensitive code defaults to deny and fails closed, with negative tests.
- Keep `/api/v1` backward compatible (see `docs/api-policy.md`).

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
PYTHONPATH=backend/. python -m pytest backend/tests -q -m "not slow"
cd frontend && npm ci && npm run build
```

## PR checklist

- [ ] Tests added/updated; suite green (fast + affected slow tests)
- [ ] `docs/openapi.json` regenerated if routes changed (`scripts/export_openapi.py`)
- [ ] `scripts/check_openapi_break.py` passes
- [ ] CHANGELOG.md entry under `[Unreleased]`
- [ ] Docs updated (DEPLOYMENT.md / THREAT_MODEL.md / relevant `docs/`)
- [ ] No secrets committed (`pre-commit install` runs gitleaks)

## Reporting bugs / requesting features

Use the issue templates. For vulnerabilities, follow `SECURITY.md` (private
report — never a public issue).
