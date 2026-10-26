# Evidence: label export + manifest hygiene (Task 7, 2026-10-26)

Branch `live-run-kit`. Tool versions: Python 3.13.12, SQLAlchemy 2.0.52.

## What ran

`PYTHONPATH=backend/. python -m pytest backend/tests/test_export_labels.py -q`
→ **11 passed** (synthetic SQLite fixtures only; no live-run or pilot data
exists anywhere in this work):

- export format matches `app.ml.retraining.build_analyst_dataset`
  (`{"session_id", "y", "source"}`; confirmed→1, false_positive→0,
  accepted_risk excluded from y), with `source="analyst"` rows and
  `source="rules"` rows in separate sections, never merged;
- provenance per label: label_id, finding_id, session_id, rule_id,
  rule_version (tool version), who, when, verdict, y, triage_category
  (parsed from the API's `[triage:<cat>]` comment prefix), comment;
- org scoping of the export;
- manifest hygiene: lab entries pass with a legacy warning (no data_class),
  live-run/pilot entries FAIL without authorization + permission +
  pseudonymized fields and pass with them; unknown data_class fails;
- the committed `tests/real/manifest.json` passes the check (errors=0,
  warnings ask the 28 legacy lab entries to add `data_class`);
- CLI roundtrip through a file-backed SQLite DB.

## API change (feedback → triage linkage)

`POST /api/v1/findings/{finding_id}/feedback` now accepts optional
`triage_category` ∈ {bug, noise, expected-behavior, documented-limitation}
(400 otherwise), stored as a machine-readable comment prefix — no schema
migration needed. Existing feedback tests still pass (field is optional);
full fast suite green after the change (287 passed, 2026-10-26).

## CI wiring

`.github/workflows/ci.yml` backend job gains a step running
`scripts/export_labels.py --check-manifest tests/real/manifest.json` after
the claims gate. The workflow itself has NOT been executed here (no
runner/credentials) — the check command was run locally with exit 0:

```
$ PYTHONPATH=backend python scripts/export_labels.py --check-manifest tests/real/manifest.json
WARN: captures[0] (...): no 'data_class' (lab|live-run|pilot) — treating as lab; new entries MUST set it
... (one per legacy entry)
manifest check OK (28 warning(s))
```

## NOT-VERIFIED

- CI workflow run with the new step (no runner access from this session).
- A real live-run/pilot label export (no such data exists; the export
  path is exercised on synthetic fixtures only).
