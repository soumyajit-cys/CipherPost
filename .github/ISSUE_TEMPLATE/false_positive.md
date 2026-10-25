---
name: False positive
about: A finding that is not actually a problem
title: "[false-positive] <rule_id>"
labels: false-positive, triage
---

## Finding

- Rule id:
- Finding id / session id (from the dashboard or API):
- Severity:
- Date/time observed (UTC):

## Why this is a false positive

What the real configuration is, and why the finding does not reflect it.
(See `docs/live-run/triage.md` for the confirmation checklist.)

## Expected behavior

What the tool should have reported instead (e.g. "no finding", "info posture note").

## Evidence bundle (required)

Attach the output of:

```bash
python scripts/export_issue_bundle.py --finding <finding_id> [--session <session_id>]
```

The bundle is redacted by default (no secrets, masked addresses). If you
confirmed the false positive by reproducing from the stored session or the
original capture, say so and include the command you used.

## Triage category

`bug | noise | expected-behavior | documented-limitation` — see `docs/live-run/triage.md`.
