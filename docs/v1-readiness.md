# v1.0 readiness (Phase 4 gate + blocker-closure lab — honest assessment)

Date: 2026-10-02 (gate); lab update 2026-10-05 ( Items closed by automation
and local lab only; nothing requiring real people/systems is claimed);
reviewed 2026-10-09 with no status changes.
Status: **STILL NOT READY for v1.0** — 3 of 8 items PASS with committed
evidence plus 1 PARTIAL (see table). Nothing here is projected or guessed.

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

## Blocker verdicts re-derived from evidence (2026-10-09 review)

Each status was re-checked against its evidence file on 2026-10-09. No item
without committed evidence is marked PASS. Downgrades applied in this review:
none — every PASS/PARTIAL below links a committed evidence file; the
previous table already marked the unrun items NOT-VERIFIED correctly.

| Item | Verdict | Evidence |
|---|---|---|
| External pilots with analyst labels | NOT-VERIFIED | No external orgs involved. Partial only: 28 lab-labeled captures in `tests/real/` (functional labels, not pilot labels), `docs/evidence/real-eval.md` |
| 30-day live-traffic run | NOT-VERIFIED | 3-minute soak only: 4.6M packets, 0 errors, RSS flat (`docs/evidence/chaos-run.md`). Owner must run the 30-day live capture. |
| Kind install of the Helm chart | NOT-VERIFIED | Workflow written-but-not-run (`.github/workflows/kind-install.yml`); 4 chart bugs fixed by review; `docs/evidence/kind-install.md`. Owner must run it. |
| Real-IdP SSO flow | PASS (Keycloak 26.8.0 only) | `docs/evidence/sso-keycloak.md`; `test_phase6_keycloak.py` (4 slow tests). MFA is app-side TOTP (unchanged); `/auth/logout` and `revoke-all` not re-run live — stated in the evidence file. No other providers. |
| Registry push, image signing, provenance | NOT-VERIFIED | Explicitly NOT passed for signing/push/provenance: release inputs only parse-checked, no runner/credentials (`docs/evidence/release-dryrun.md`). Owner action required. |
| Nightly chaos on real infrastructure | PARTIAL | PASS: real-Redis outage test + soak (`docs/evidence/chaos-run.md`). NOT-VERIFIED remainder: true Postgres restart, container worker kills, CI nightly run. |
| Independent JA4/JA4S verification | PASS (within what exists) | Spec worked example MATCH; JA4S layout verified vs reference behavior, 1 real mismatch fixed; `docs/evidence/ja4-verification.md`. No official numeric JA4S vector exists. |
| Post-quantum interop | PASS | 4 live handshakes (hybrid/classic/gap/HRR) + abort control, tshark agreement, 1 parser bug fixed; `docs/evidence/pq-interop.md`, 5 captures in `tests/real/`. |

## Gate decision (unchanged in substance)

Still **NOT READY for v1.0**: external pilots, the 30-day run, the kind run,
registry push/sign/provenance, and the remainder of chaos need
real people, real time, real systems, or owner credentials — none of which
automation can supply. What the lab closed (Real-IdP SSO for Keycloak,
JA4/JA4S, PQ interop, half of chaos) is evidenced above; everything else
lists exactly what the owner must do. Do not tag v1.0
until pilots plus a green kind run exist as artifacts, not plans.

Last verified: 2026-10-09 — statuses re-derived from evidence files
(`docs/evidence/real-eval.md`, `chaos-run.md`, `sso-keycloak.md`,
`ja4-verification.md`, `pq-interop.md`, `release-dryrun.md`,
`kind-install.md`, `diff-tshark.md`); toolchain OpenSSL 3.6.1, tshark 4.6.4,
Keycloak 26.8.0, Python 3.13. Interop claims in this file (JA4/JA4S, PQ
groups, SSO) are scoped to those versions and that lab only.
