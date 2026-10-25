---
name: Missed detection
about: Something you expected CipherPost to flag but it did not
title: "[missed-detection] <what you expected>"
labels: missed-detection, triage
---

## What you expected to be detected

The configuration or behavior you believe should produce a finding
(e.g. "server negotiated TLS 1.0 on submission").

## What the tool actually reported

Rule ids, severities, and session ids — or "nothing".

## Could the capture point have seen it? (required)

Per `docs/live-run/triage.md`: a miss is only a miss if the capture point
could have observed the evidence. State:

- which placement the sensor had (host / SPAN / sidecar — see
  `docs/live-run/capture-placement.md`);
- whether TLS 1.3 hides the evidence (certificate rules legitimately skip
  TLS 1.3 — that is a documented limitation, not a miss);
- what the capture *should* contain (e.g. "ServerHello with 0x0301 selected").

## Expected behavior

The rule you expected to fire and the severity you consider correct.

## Evidence bundle (required)

```bash
python scripts/export_issue_bundle.py --session <session_id>
```

If the session was not captured at all, attach a `tcpdump`/`tshark` excerpt
from the capture point (redacted) instead, plus `cipherpost doctor` output.

## Triage category

`bug | noise | expected-behavior | documented-limitation` — see `docs/live-run/triage.md`.
