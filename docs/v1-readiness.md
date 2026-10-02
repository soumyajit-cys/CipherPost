# v1.0 readiness (Phase 4 gate — honest assessment)

Date: 2026-10-02. Status: **NOT READY for v1.0**. Ship as 0.4.0-RC after
review; v1.0 requires the blockers below. Nothing in this file is projected
or guessed — unverified items say so explicitly.

## What Phase 4 delivered (all tested, on `main`)

- **TLS 1.3 visibility model**: per-session `visibility` + `not_observable`
  lists; cert rules skip (never pass/fail) blind TLS 1.3; reports and fleet
  APIs roll up limitations. See `docs/what-we-cannot-see.md`.
- **JA3/JA4 fingerprints**: spec-derived implementation (FoxIO JA4 spec,
  retrieved 2026-10-02), GREASE-stripped, stored per session, per-flow
  history, org allow/deny lists with import/export. JA4S layout is
  **EXPERIMENTAL** (spec text is diagram-only) and labeled as such in output.
- **Post-quantum posture**: offered-vs-negotiated hybrid PQ facts per session,
  `/api/v1/posture/quantum` per flow/org. **Informational only — never a
  finding** (policy `informational` default; `warn` only lists attention).
- **Trustworthy ML**: grouped time-aware splits (no leaked server groups;
  legacy random split shown to leak 2 groups on the same corpus),
  analyst-label retraining with minimum-data gate (50/class default →
  ranking-only below), promotion margin + FP-regression gate, one-click
  rollback, per-org models, PSI drift + Prometheus alert + runbook + fleet
  panel + SHAP honesty disclaimer.
- **Alert quality**: measured per-rule precision/volume/TTA/suppressions at
  `/api/v1/alerts/quality` + dashboard; ownership routing, per-org severity
  policy, digests, quiet hours (critical always bypasses); per-alert explain
  with remediation snippets **only where verified** (Postfix TLS_README,
  retrieved 2026-10-02). No rule severities changed — with no pilot label
  data, changes would be intuition, not evidence.
- **Compliance + evidence**: mapping moved to versioned data
  (`mapping-v1.json`, `mapping_version == 1`, exposed on the API); all Phase
  4 rules mapped; hash-chained evidence bundles via CLI (`cipherpost
  evidence`) and `GET /api/v1/jobs/{id}/evidence`, with verify + tamper
  tests.

## Verification performed (2026-10-02)

- `pytest backend/tests -m "not slow"`: **202 passed**, 6 deselected.
- `tsc -b frontend`: clean.
- Alembic: fresh-DB `upgrade head` + `check` clean (scratch DB rebuild).
  Known caveat (pre-existing, documented in DEPLOYMENT.md): full
  `downgrade base` rebuild fails on frozen Phase 1 ENUM types; stepwise
  down/up verified.
- OpenAPI baseline refreshed; `check_openapi_break.py`: no breaking changes
  (80 paths).
- Corpus eval: rules reproduce ground truth exactly (45 findings, 0 FP/FN on
  the synthetic corpus); ML corpus numbers are smoke tests only
  (16 synthetic sessions, both splits score 1.0 — see `docs/ml-evaluation.md`).

## Last measured performance (toy-scale only, NOT a claim)

- 261-packet synthetic corpus; Ryzen 7 5700G: ~28k pkt/s, 1-min soak
  0 errors, RSS flat 47.6 MB. Do not size production from this table —
  replay your own capture per `docs/sizing.md`.

## v1.0 blockers (all NOT DONE — not observable, not claimed)

1. Three external pilots with analyst labels (precision, TTA, noise) — none
   in repo; `tests/real/manifest.json` has zero captures.
2. 30-day live-traffic run (drops, DLQ, drift, storage growth).
3. kind install of the Helm chart (lint/template/kubeconform 13/13 only).
4. Real-IdP SSO flow (code tested with fakes only).
5. Registry push/sign + provenance on real infra.
6. Nightly chaos suite on real infra (unit chaos only).
7. Independent JA4S verification (single implementation; self-derived vectors).
8. PQ interop against real hybrid servers (classification only, no live captures).

## Gate decision

Merge Phase 4 as **0.4.0-RC1** (or 0.4.0) after review. Promote to v1.0 only
after blockers 1–2 plus chart install (3) are evidenced by pilot artifacts,
not by code alone.
