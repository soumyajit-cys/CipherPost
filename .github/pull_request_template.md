## Summary (one paragraph, facts only)

## Type
- [ ] bug fix
- [ ] feature
- [ ] docs / chore

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
