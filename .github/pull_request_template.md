## Summary (one paragraph, facts only)

## Type
- [ ] bug fix
- [ ] feature
- [ ] docs / chore

## Checklist (all required)
- [ ] Tests run (`PYTHONPATH=backend python -m pytest backend/tests -q -m "not slow"` green, or state what failed and why)
- [ ] Existing assertions untouched (no weakened/skipped/edited assertions; if one had to change, explain exactly why below)
- [ ] Evidence added under `docs/evidence/` for any claim (command + output excerpt + tool versions), or marked NOT-VERIFIED with what is missing
- [ ] Claims match evidence (no new accuracy/interop/production claims beyond the evidence files)
- [ ] No secrets committed (no credentials, tokens, or customer captures)
- [ ] Docs updated (README/CHANGELOG/THREAT_MODEL/docs as applicable)

## Verification (commands you actually ran + results)
- [ ] `PYTHONPATH=backend/. python -m pytest backend/tests -q -m "not slow"` green
- [ ] New tests fail before / pass after (name them):
- [ ] `scripts/check_openapi_break.py` passes (if routes changed)
- [ ] `docs/openapi.json` regenerated (if routes changed)

## Migrations
- [ ] No schema change, or new migration with upgrade + downgrade, `alembic check` clean

## Docs
- [ ] CHANGELOG.md entry
- [ ] Relevant docs updated

## What you could NOT verify (and why)
