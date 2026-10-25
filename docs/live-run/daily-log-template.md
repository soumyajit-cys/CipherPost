# Daily log — live run (template)

Copy this file each day to `docs/live-run/logs/YYYY-MM-DD.md` (or your own
store) and fill it in. Plain text, facts over interpretation; anything
unknown stays unknown. This is a template — it contains no results.

```markdown
# Live-run daily log — YYYY-MM-DD

## What changed today (config, restarts, network, hosts)

- (none | e.g. "restarted capture container 14:05 UTC after OOM")

## Anomalies

- (none | what was seen, when (UTC), which alert/flag/report line surfaced it)

## Suspected false positives

| finding id | rule | why suspected | triage action taken |
|---|---|---|---|
| | | | exported bundle / labeled via feedback UI / still open |

## Suspected misses (expected vs saw)

| expected (what should have been detected) | saw (what the tool reported) | capture point could see it? | action |
|---|---|---|---|
| | | yes/no + why | |

## Operational problems

| problem | time (UTC) | resolved? | how |
|---|---|---|---|
| | | | |

## Numbers (from `scripts/live_report.py` --start YYYY-MM-DD --end YYYY-MM-DD)

- sessions: N (prev period: N) — flags: (none | list)
- findings by severity: info N / low N / medium N / high N / critical N
- dead-letter depth: N; capture drops: (none | counters)
- zero-session hours: (none | list)

## Feedback labels recorded today

- confirmed: N; false_positive: N; accepted_risk: N (rule ids for any new false_positive)

## Time spent

- total: Xh Ym (triage Xh, ops Xh, other Xh)

## Severity today

- (none | S3 | S2 | S1) — scale in docs/live-run/triage.md

## Notes / follow-ups for tomorrow

- [ ]
```

Rules of thumb:

- Never paste message bodies, credentials, or full addresses into the log —
  reference finding ids and session ids instead.
- Attach an issue bundle (`scripts/export_issue_bundle.py`) rather than
  screenshots of raw traffic.
- If nothing happened, write "(none)" — an explicit quiet day is data for
  the run's exit criteria; a blank section is not.
