---
name: Operational failure
about: The pipeline itself failed (capture, analysis, delivery, storage)
title: "[ops] <component>"
labels: operational
---

## What failed

Component and symptom (capture stopped, sessions dropped, alerts not
delivered, disk full, dead-letter depth growing, ...).

## When it started and what changed

Date/time (UTC) and any recent change (restart, config edit, certificate
rotation, disk pressure).

## How you noticed

Which report flag / runbook alert / dashboard signal fired — e.g.
`live_report` `capture-stop-suspected`, `/api/v1/live/status` DLQ depth.

## Expected behavior

The service should have kept running / alerted / recovered per
`docs/runbook.md`.

## Evidence bundle (required)

```bash
python scripts/export_issue_bundle.py --session <session_id>   # if session-related
# plus:
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/v1/diagnostics/bundle > diagnostics.json
```

The diagnostics bundle is redacted by default. Include
`cipherpost doctor` output if available.

## Environment

- CipherPost version / image tag:
- Install path (compose / Helm / systemd):
- Host resources (vCPU / RAM / disk free at the time):
