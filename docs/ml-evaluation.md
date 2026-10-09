# ML evaluation: grouped splits, honest numbers

Command: `PYTHONPATH=backend python -m app.ml.eval_ml tests/fixtures [--compare]`
Labels below are rules-derived (`source=rules`); analyst-labeled evaluation
(`source=analyst`) is reported separately once labels exist.

## Corpus results (16 synthetic sessions, 2026-10-02)

| Split | Train / test | Leaked server groups | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|---|
| Grouped, time-aware (whole servers, newest to test) | 13 / 3 | **none** | 1.0 | 1.0 | 1.0 | n/a (single-class test) |
| Legacy random row-wise | 12 / 4 | **2** (`192.168.1.20:587`, `:993`) | 1.0 | 1.0 | 1.0 | 1.0 |

## What this means (no hiding)

- There is **no measurable metric drop** here — and that proves nothing. The
  corpus is 16 trivially separable synthetic sessions; both splits score 1.0.
- What IS proven: the legacy split leaks server groups across train/test
  (half its test set shares servers with training), so any accuracy it
  reports on real data would be overstated. The grouped split leaks nothing.
- A meaningful grouped-vs-random delta requires analyst-labeled sessions at
  real scale (see minimum-data policy below). Until then, treat all corpus
  ML numbers as smoke tests, not evidence.

## Label sources (never mixed silently)

- `source=rules`: y from rule severity (medium+ = at-risk). Abundant but
  circular — good for smoke tests only.
- `source=analyst`: y from FindingFeedback verdicts (`confirmed` on a
  medium+ finding = 1, `false_positive` = 0, `accepted_risk` excluded).
  Metrics are reported per source; mixed training is rejected by the
  retraining gate.

## Minimum-data policy

Training or promotion requires at least `MIN_ANALYST_LABELS_PER_CLASS`
analyst labels per class (default **50**, `CIPHERPOST_MIN_ANALYST_LABELS`).
Below threshold the system stays in ranking-only mode and the API/UI say so
(`ml_mode: "ranking-only"`); scores reorder review queues but decide nothing.

## Retraining, promotion, rollback

`POST /api/v1/ml/retrain` (admin) builds a candidate on analyst labels:
dataset hash, code version, feature schema, and grouped held-out metrics go
in the registry. Promotion requires beating the current model by
`ML_PROMOTE_MARGIN_F1` (default 0.02) with no per-rule false-positive-rate
regression; otherwise the candidate is rejected with a recorded reason.
`POST /api/v1/ml/rollback` restores the previous version (one click).

Last verified: 2026-10-05 — grouped-split honesty result and ranking-only
policy on the 16-session synthetic corpus plus 28 lab captures (94
sessions); analyst-label path untested for lack of labels. Evidence
`docs/evidence/real-eval.md`.
