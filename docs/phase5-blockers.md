# Phase 5 gate check: BLOCKED — v1.0 foundation not met

Date: 2026-10-05; consistency review 2026-10-10. Verdict: **STOP. Do not
start Phase 5 Tasks 1–8.** Source of truth for per-item verdicts is
`docs/v1-readiness.md` (name-based PASS/PARTIAL/FAIL/NOT-VERIFIED with
evidence links); this file is the risk-ranked gate narrative and is kept
consistent with it. Items 1–10 below retain their original numbers for
audit traceability; v1-readiness uses names (no numbers).

Evidence (all observed in-repo on 2026-10-05):

- `docs/v1-readiness.md` (2026-10-02): Status line reads **"NOT READY for
  v1.0"** with 8 blockers listed as NOT DONE.
- `git tag`: **no tags** — v1.0 (or 0.4.0-RC) has not been tagged by the owner.
- `tests/real/manifest.json`: `"captures": []` — zero real captures.
- `README.md` "Maturity" section: "no external organization has piloted it
  yet. **A minimum of three external pilots is required before any v1.0
  label.**"
- Open issues / pilot feedback in repo: **none found** — no issue exports,
  no pilot notes beyond `docs/pilot-guide.md` (which is a guide for future
  pilots, not feedback). `.github/ISSUE_TEMPLATE` exists but no filed issues
  were located.

## Unmet items, work to close, risk ranking

Risk = risk of building Phase 5 (extensibility, integrations, scale,
hosted analysis) on top of this unreleased foundation.

1. **Three external pilots with analyst labels — MISSING (risk: HIGH).**
   Close: run the `docs/pilot-guide.md` 1-hour install + 2-week measurement
   loop at three external orgs; collect findings/day per rule, precision
   labels via finding feedback, TTA, noise reports; archive artifacts
   (diagnostics bundles, precision exports). Without this, Tasks 1 (rule
   SDK), 2 (SIEM/SOAR choice), and 4 (protocol coverage) have no demand
   evidence, and the prompt itself says to drop tasks with no evidence.

2. **30-day live-traffic run — NOT DONE (risk: HIGH).**
   Close: continuous capture on real SPAN/TAP traffic for 30 days; record
   drops, DLQ depth, drift events, storage growth, alert volumes. Without
   this, Task 3 (scale-out/storage) has no measurements to justify changes,
   and Task 5 SLOs would be invented numbers.

3. **kind install of the Helm chart — NOT DONE (risk: MEDIUM).**
   Close: `kind create cluster`, install chart, verify probes/migrations/
   ingest end-to-end (current evidence is lint/template/kubeconform only).
   Phase 5 operational work (Task 5 doctor, upgrade automation) assumes a
   deploy path that has never been executed.

4. **Real-IdP SSO flow — PASS for Keycloak 26.8.0 only, NOT-VERIFIED for
   other providers (risk: MEDIUM for non-Keycloak).**
   Lab-closed 2026-10-05: verified against real Keycloak 26.8.0 (code+PKCE,
   mapping, rotation, expiry, deprovision — `docs/evidence/sso-keycloak.md`);
   MFA is app-side TOTP (unchanged); `/auth/logout` and `revoke-all` not
   re-run live. No other providers claimed. Consistent with v1-readiness
   "Real-IdP SSO flow: PASS (Keycloak 26.8.0 only)".

5. **Registry push / image sign + provenance — NOT DONE (risk: MEDIUM).**
   Close: push, cosign-sign, and verify provenance on real infra per the
   release workflow. Task 1 pack signing policy and Task 8 supply-chain
   checks build on signing practices never exercised end-to-end.

6. **Nightly chaos suite on real infra — PARTIAL (risk: MEDIUM).**
   Lab-closed half: real-Redis outage + 3-min soak pass
   (`docs/evidence/chaos-run.md`). Still NOT-VERIFIED: true Postgres restart,
   container worker kills, CI nightly run. Consistent with v1-readiness
   "Nightly chaos: PARTIAL".

7. **Independent JA4S verification — PASS within what exists (risk: LOW
   residual).**
   Lab-closed 2026-10-05/09: spec worked example MATCH; JA4S layout verified
   vs reference behavior (`docs/evidence/ja4-verification.md`; GREASE handling
   behind `JA4S_INCLUDE_GREASE`, claim "verified against reference code only,
   spec text ambiguous"). No official numeric JA4S vector exists. Consistent
   with v1-readiness "Independent JA4/JA4S verification: PASS".

8. **PQ interop against real hybrid servers — PASS lab-only (risk: LOW
   residual).**
   Lab-closed 2026-10-05: 4 live handshakes (hybrid/classic/gap/HRR) + abort
   control with tshark agreement, 1 parser bug fixed
   (`docs/evidence/pq-interop.md`, 5 captures in `tests/real/`). No
   third-party servers contacted; scope is OpenSSL 3.6.1 loopback only.
   Consistent with v1-readiness "Post-quantum interop: PASS".

9. **v1.0 (or 0.4.0-RC) tag by owner — NOT DONE (risk: HIGH, process).**
   Close: owner reviews `docs/v1-readiness.md`, tags the release. Phase 5
   migrations must be tested "on a populated database from the oldest
   supported release" — with no tagged release, there is no defined oldest
   supported release, so upgrade/rollback testing has no baseline.

10. **No issue/feedback corpus for prioritization — EMPTY (risk: HIGH).**
    Close: file pilot issues (or export tracker issues into the repo) so
    Tasks 1–8 can be ranked by evidence as the prompt requires. With zero
    issues and zero pilot notes, any priority order would be invented.

## Update 2026-10-05 (blocker-closure lab — automation + local lab only)

Closed by lab work (evidence-linked, `docs/evidence/`):
- Item 4 (real-IdP SSO) → CLOSED for Keycloak 26.8.0 (`sso-keycloak.md`).
- Item 7 (JA4S verification) → CLOSED within what exists (`ja4-verification.md`).
- Item 8 (PQ interop) → CLOSED (`pq-interop.md`, 5 captures).
- Item 6 (chaos on real infra) → HALF-CLOSED (real-Redis outage + soak pass;
  PG restart, container kills, CI nightly run still open).

Still open (owner-only): items 1 (external pilots), 2 (30-day run),
3 (kind run), 5 (registry/sign credentials), 9 (tagging), 10 (feedback
corpus), and the remainder of 6. New sub-blockers discovered are logged in
`docs/known-issues.md` (diff_tshark field gap, hostname-mismatch live path,
FIN-less stream drops, JA4S numeric-vector absence).

Re-ranked by risk now: 9/1/2 (process + pilots + live run — HIGH, gate v1.0),
3/5 (MEDIUM, need owner runs/credentials), remainder of 6 + 10 (MEDIUM),
2/7-residuals (LOW).

## Recommendation (unchanged)

Close items 1–2 (pilots + 30-day run) and item 9 (tag a release) first, then
run the kind workflow (3) and the release pipeline with credentials (5).
Re-run this gate after that. Phase 5 feature Tasks 1–8 remain deferred.
