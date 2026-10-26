# Pilot metrics (what to collect per pilot, and how to aggregate safely)

All per-pilot numbers come from `scripts/live_report.py` output files plus
the feedback/label exports — the same definitions as
`docs/live-run/report-reference.md`. This file defines the pilot overlay:
what to collect, cadence, and the aggregation rules that keep any one
pilot's data from being exposed.

## Per-pilot collection (weekly, from live-report files)

| Metric | Source field | Notes |
|---|---|---|
| Coverage | `gaps_zero_session_hours` (count) | excludes pre-agreed maintenance windows |
| Volume | `sessions.total`, `sessions.total_previous` | |
| Encryption posture | `sessions.encrypted_share`, `tls_versions` | |
| Findings pressure | `findings.by_severity`, `findings.by_rule` (top 5) | |
| Label yield | `feedback` (confirmed / false_positive / accepted_risk) | from the same window |
| Label precision | `confirmed / (confirmed + false_positive)` per rule (top 5 by volume) | undefined while denominator < 5 — report `n/a`, never 0% |
| Pipeline health | `pipeline_health` (lag, dlq, drops), `alert_delivery_failures` | |
| Triage load | count of issue bundles exported (from GitHub issues) | time-to-triage from daily logs |

Plus one-time (onboarding/exit): install duration vs target, preflight
FAIL items at start, survey answers (quoted only with permission).

## Aggregation rules across pilots (the part that must not leak)

1. **Minimum cohort size 3.** No aggregate is published (internally or
   externally) from fewer than 3 pilots; if only 2 pilots supplied data
   for a metric, it is reported as "insufficient pilots", never as a
   number.
2. **No per-pilot attribution in aggregates.** Published aggregates carry
   only cohort-level values (median/range across pilots), never a value
   traceable to one organization. Ranges that would identify a single
   pilot (cohort of 3 → min=max pilot) are reported as a median only.
3. **Precision shares use labeled rules only**, with the per-rule
   minimum-denominator rule above; unlabeled volume is reported
   separately as "unlabeled".
4. **Quotes and survey text** only with the written permission level the
   pilot chose on the survey form.
5. **Issue bundles** are confidential by default
   (`pilot-agreement-outline.md` §7); aggregate counts of bundles by
   triage category are publishable, bundle contents are not.
6. **No pilot's data enters `tests/real/`** — live-run/pilot captures are
   kept out of the lab test set unless the explicit, authorized import
   path (`scripts/export_labels.py --allow-live`) is used with source,
   authorization, and permission fields filled and pseudonymization
   applied. The default is and stays "never mix".

## Where the numbers live

- Per pilot: `docs/pilot/records/<pilot-id>/week-N.md` (private to the
  owner + that pilot), generated from live-report JSON so definitions
  never drift from `report-reference.md`.
- Cross-pilot aggregate sheet: `docs/pilot/records/aggregate.md`, updated
  only from the per-pilot files, following the rules above.
