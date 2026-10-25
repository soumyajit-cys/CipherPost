# Live-report metric reference

Every metric emitted by `scripts/live_report.py` (run as
`python scripts/live_report.py --start <date> --end <date> [--org-id <org>]
[--out <prefix>] [--no-pipeline] [--flag-pct N]`), in execution order.
This file is the single source of definitions; the script links here.
All times are UTC. All session/finding metrics are **org-scoped** when
`--org-id` is given and include every org when it is not.

## Window semantics

- `window`: `[start, end)` — ISO datetimes. A date-only `--end` means the
  end of that day (23:59:59), so `--start D --end D+1` covers a full day.
- `previous_window`: the immediately preceding interval of the same length;
  every comparison is against it.

## Session metrics (table `sessions`, filter `created_at` in window)

| Metric | Definition |
|---|---|
| `sessions.total` | COUNT of session rows with `created_at` in window. |
| `sessions.total_previous` | Same COUNT over `previous_window`. |
| `sessions.per_day` | COUNT grouped by day (first 10 chars of the UTC timestamp). |
| `sessions.per_protocol` | COUNT grouped by `protocol` (SMTP/IMAP/POP3 as stored). |
| `sessions.encrypted` | COUNT where `tls_version IS NOT NULL` — the capture observed a negotiated TLS version. |
| `sessions.plaintext` | COUNT where `tls_version IS NULL` — no completed TLS handshake was observed on the session (includes STARTTLS-capable sessions that never upgraded; see `docs/what-we-cannot-see.md` for the strip caveat). |
| `sessions.encrypted_share` | `encrypted / total`, rounded to 4 decimals; `null` when total is 0. |
| `sessions.tls_versions` | COUNT grouped by `tls_version` (`'none'` for NULL). |
| `sessions.ciphers` | COUNT grouped by `negotiated_cipher` (`'none'` for NULL). Markdown renders the top 10 and buckets the rest as `_other`. |

## New-observation metrics (first appearance **inside** the window)

| Metric | Definition |
|---|---|
| `new_flows` | DISTINCT `five_tuple` values whose earliest-ever `created_at` (over all history, org-scoped) falls inside the window. A flow seen in earlier periods is not new even if it recurs. |
| `new_fingerprints` | DISTINCT non-null client `ja4` values whose earliest-ever `created_at` falls inside the window. |

## Finding metrics (tables `findings` JOIN `sessions`, window on `findings.created_at`)

| Metric | Definition |
|---|---|
| `findings.by_rule` | COUNT grouped by `rule_id`, descending. |
| `findings.by_severity` | COUNT grouped by severity, lower-case (`info|low|medium|high|critical`). Severity is stored as the enum member name (`HIGH`); the report normalizes to lowercase. |

## Feedback and suppressions

| Metric | Definition |
|---|---|
| `feedback` | COUNT of `finding_feedback` rows grouped by `verdict` (`confirmed|false_positive|accepted_risk`) with `created_at` in window (org-scoped). |
| `suppressions.created_in_window` | COUNT of `suppressions` rows with `created_at` in window (org-scoped). |
| `suppressions.active_at_end` | COUNT of `suppressions` rows (org-scoped) with `expires_at > window end`, regardless of creation date. |
| `alert_delivery_failures` | COUNT of `alert_deliveries` rows with `status='failed'` and `ts` in window (org-scoped). |

Suppressed *findings* are not counted historically: suppression is a rule
scope (`suppressions`), and findings are marked suppressed only at query
time, not stored per-row. What the report counts is suppression
configuration activity, not per-finding suppressions.

## Pipeline health (opt-in; local Redis only)

Collected by `collect_pipeline_health()` unless `--no-pipeline`. Best-effort:
on any failure the report carries `pipeline_health.error` instead of numbers.

| Metric | Definition |
|---|---|
| `consumer_lag` | XLEN of the sessions stream (`cipherpost:sessions`) — unprocessed entries waiting for analyzers. |
| `dlq_depth` | XLEN of the sessions dead-letter stream (`<stream>:dlq`) — poison messages that exhausted retries. |
| `capture_drops` | Sum of every `cipherpost:metrics:*` gossip counter whose name contains `dropped` (buffer-full publish drops, evicted/over-cap sessions). |
| Restarts | **Not measured.** There is no restart counter in the current metrics set; use process supervision (systemd `NRestarts`, container restart counts) and treat repeated `agent heartbeat` gaps in `GET /api/v1/agents` as the proxy. Recorded here honestly rather than guessed. |

## Gaps

| Metric | Definition |
|---|---|
| `gaps_zero_session_hours` | Every hour bucket `[HH:00, HH+1:00)` intersecting the window in which the org-scoped session COUNT is zero. Buckets are keyed `YYYY-MM-DD HH` (UTC). |

## Flags (exit code 1 when non-empty)

Comparisons use the previous period of equal length; `--flag-pct` sets the
percentage threshold (default 50).

| Flag | Fires when |
|---|---|
| `capture-stop-suspected` | `total == 0` while `total_previous > 0` — the single most likely signature of a stopped capture. |
| `sessions-drop` | `total` fell by at least `flag_pct`% vs `total_previous`. |
| `coverage-gap` | `gaps_zero_session_hours` is non-empty. |
| `dead-letter-spike` | `pipeline_health.dlq_depth > 0`. |
| `consumer-lag` | `pipeline_health.consumer_lag > 1000` (matches the CipherPostConsumerLagGrowing runbook threshold). |
| `capture-drops` | any `capture_drops` counter is non-zero. |
| `alert-delivery-failures` | `alert_delivery_failures > 0`. |

No flag fires on the first populated period (`total_previous == 0`,
`total > 0`) — there is nothing to compare yet.

## Privacy contract

- The report reads only the local database (and, unless `--no-pipeline`,
  the local Redis). **Nothing is sent anywhere.**
- Addresses and five-tuples are never printed in either output; counts and
  distributions only. If address display is ever added, it must go through
  `app.agent.meta.redact_host` with the deployment's `addr_mode`
  (`hashed` being the safe default), respecting pseudonymization settings.
- Exit codes: `0` no flags, `1` flags present (actionable), `2` usage error.
