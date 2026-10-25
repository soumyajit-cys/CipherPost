# Weekly check-in template (pilot, weeks 1–4+)

Fill together with the pilot analyst; 20–30 minutes. Numbers come from
`scripts/live_report.py` and the dashboard — never hand-typed from memory.
No results exist in this template.

```markdown
# Pilot weekly check-in — <org> — week N (dates)

## 1. Health (from live-report, attach file)

- Sessions this week vs last: ___ / ___ (flags: none | list)
- Pipeline: consumer lag ___ , DLQ depth ___ , capture drops ___ ,
  alert delivery failures ___
- Coverage gaps (zero-session hours): none | list
- Open operational issues: none | ids

## 2. Findings quality

- Findings by severity this week: info _ / low _ / medium _ / high _ / critical _
- New rules seen this week (rule ids): none | list
- Labeled this week: confirmed _ / false_positive _ / accepted_risk _
- Suspected false positives (with finding ids + one-line why):
- Suspected misses (what you expected vs what the tool showed):

## 3. Install / operation friction

- Anything from onboarding still hurting? (none | describe)
- Docs that were wrong or missing? (none | which)

## 4. Usefulness

- Did any finding lead to an action? (none | what: config change / ticket / investigation)
- Which remediation steps were clear vs confusing? (cite rule ids)

## 5. Performance / ops concerns

- Resource use on the pilot host (CPU/RAM/disk free, from `docker stats` or doctor):
- Concerns: none | describe

## 6. Actions and owners

- [ ] action — owner — due
- [ ] action — owner — due

## 7. Willingness to continue

- Continue as planned / continue with changes / pause / stop — one line why.
```

Aggregation note for us: weekly sheets are inputs to `pilot-metrics.md`
aggregation; never publish a single pilot's numbers externally.
