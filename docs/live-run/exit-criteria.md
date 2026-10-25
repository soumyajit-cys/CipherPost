# 30-day live-run exit criteria (TEMPLATE — contains no results)

**Status: this file is a template to fill in during and after the run. It
contains NO results, and nothing in it may be cited as a pass/fail outcome
of the live run.** The live run has not happened. When evidence exists,
fill the `Result` column, link the evidence files, and update
`docs/v1-readiness.md` — which will still say NOT-VERIFIED until then.

## What the run is

- Duration: 30 consecutive days on the owner's own mail server
  (dates: ______ to ______).
- Capture point: ______ (host-mode / SPAN / sidecar — per
  `docs/live-run/capture-placement.md`).
- Authorization: the owner's own infrastructure only; no third-party mail
  servers contacted; external senders only with consent (see
  `docs/live-run/setup.md`, "Honest limits").

## v1-readiness items this run can (partially) close

From `docs/v1-readiness.md` — the table below states exactly which items the
run can move and what evidence is required. The run **cannot** close:
external pilots (different activity), kind install, registry push/sign, or
anything else listed there as owner/pilot work.

| v1-readiness item | What the run must produce | Result (fill in) |
|---|---|---|
| 30-day live-traffic run (currently NOT-VERIFIED) | 30 daily logs (`docs/live-run/daily-log-template.md`), 30 live-report JSON/MD pairs, uptime/coverage statement | ______ |
| Nightly chaos remainder (ops-side items only) | Recorded incident responses (ops checklist usage), any restarts/failures and recovery notes | ______ |
| Pilot readiness (indirect input only) | Issue-bundle counts, triage category distribution, precision-by-rule from labels | ______ |

## Evidence the run produces (inventory)

1. **Daily logs**: 30 files `docs/live-run/logs/YYYY-MM-DD.md` (template:
   `daily-log-template.md`), each with anomalies, suspected FPs/misses,
   operational problems, time spent, severity.
2. **Reports**: daily `scripts/live_report.py` output (`--out
   docs/live-run/reports/YYYY-MM-DD`), JSON + Markdown, flags included.
3. **Issue bundles**: `scripts/export_issue_bundle.py` outputs attached to
   GitHub issues (count: ______; false-positive: __, missed: __, ops: __).
4. **Labels**: `scripts/export_labels.py` export with provenance, kept
   separate from `tests/real/` (never mixed into the lab test set).
5. **Coverage statement**: total zero-session hours across the run
   (from reports), and which windows are excluded and why.
6. **Ops checklist records**: `docs/live-run/ops-checklist.md` daily/weekly
   items with dates.

## What counts as FAIL (explicit)

Any of the following fails the run for readiness purposes — the readiness
record stays NOT-VERIFIED and the failure is documented in
`docs/known-issues.md`:

- Coverage below **80%** of the 30 days (excluding operator-scheduled
  maintenance windows that are logged in advance) — a capture that was
  blind for a week proves nothing about 30-day behavior.
- Any **silent** failure mode discovered: data loss, drops, or a stopped
  capture that was *not* surfaced by a report flag, alert, or health status.
  (Finding failures is fine; failing to notice them is the FAIL.)
- Unexplained crashes requiring manual recovery more than ___ times
  (fill threshold before the run; suggested: 2).
- Disk guard or retention failing to stop unbounded growth (disk-full
  incident during the run).
- Metrics pipeline integrity: report counts contradict the database
  (spot-check fails) or `check_claims.py`-style overstatement creeping into
  run documentation.
- A S1 incident left unresolved > 24 h without a documented decision.

## What the run does NOT prove (even on PASS)

- Precision/recall on traffic other than the owner's mail flows.
- Multi-tenant, multi-site, or high-link-rate behavior (see
  `docs/sizing.md` — no Mbps claim exists).
- Suitability for any other organization's compliance obligations.
- v1.0: pilots (3+ external orgs), kind install, and registry runs remain
  blockers regardless of the run's outcome.

## Fill-in checklist (owner, after the run)

- [ ] All 30 daily logs present (or gaps listed with reasons)
- [ ] All 30 report files present and linked
- [ ] Issue bundles attached to filed issues (counts above)
- [ ] Labels exported with provenance; lab test set untouched
- [ ] Coverage statement written; exclusions justified
- [ ] FAIL table walked item by item with evidence links
- [ ] `docs/v1-readiness.md` updated (statuses + evidence links only)
- [ ] `docs/known-issues.md` updated with anything new found
- [ ] `scripts/check_claims.py` run on the final docs
