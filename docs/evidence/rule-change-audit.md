# Task 5 evidence: rule/label change audit (2026-10-09)

First real-capture evaluation: commit cb80270 (2026-10-05, 5 PQ captures).
Every later commit touching rules, severities, thresholds, fingerprints, or
labels is listed below with a one-line summary. No intent judged — facts only.

| Commit | Files | Summary | Eval coincidence |
|---|---|---|---|
| cb80270 | rules, manifest, 5 pcaps | First captures + ServerHello key_share fix | Baseline established here (0 FP/FN on 5) |
| a989a6d | ja4.py, tests | JA4S GREASE parity fix (fingerprint output change) | Fingerprint-only; rule eval unaffected (verified: full suite green) |
| ce61bca | rules.py | Zero-byte guard: no cleartext findings on 0-byte sessions | Cannot flip any labeled outcome: every `present:true` plaintext label sits on a dialog session with bytes>0; junk sessions carry no labels. Current eval: 0 FP/FN |
| 51dcd89 | manifest, 23 pcaps | 23 mail captures + config-derived labels added | Labels written from server config before running the tool; eval then showed 0 misses/FPs |
| 5d78090 | manifest.json | Restored PQ entries dropped by rewrite | Restored, did not alter, labels |
| c303a25 | generator.py | Standing strip caveat in report limitations | Reporting text only; no rule/threshold/label change |
| a8c6287 | ja4.py docstring | JA4S constant documentation | Comment only |
| 746eaea + Task 5 | audit_labels.py, manifest fields | `source_config`/`provenance` fields added (23 complete, 5 partial) | Metadata only; labels untouched (eval re-run: 28 captures, 94 sessions, 0 FP/FN) |

No change above coincides with an eval result change: the only
result-altering rule edit (ce61bca) predates the mail labels and is
provably neutral to them (see row); fingerprint edits do not feed rules
(rule_* features exclude JA3/JA4 strings — only the `rule_other` catch-all
sees new rule IDs, and no new rule IDs were added since).
