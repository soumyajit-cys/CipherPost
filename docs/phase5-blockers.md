# Phase 5 gate check: BLOCKED — v1.0 foundation not met

Date: 2026-10-05. Verdict: **STOP. Do not start Phase 5 Tasks 1–8.**

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

4. **Real-IdP SSO flow — NOT DONE (risk: MEDIUM).**
   Close: verify against a real OIDC provider (generic; no vendor claims),
   covering rotation, JIT, and lockout paths currently tested with fakes
   only. Task 5 support-policy security-fix SLAs and Task 6 governance
   touch auth surfaces that are unverified against reality.

5. **Registry push / image sign + provenance — NOT DONE (risk: MEDIUM).**
   Close: push, cosign-sign, and verify provenance on real infra per the
   release workflow. Task 1 pack signing policy and Task 8 supply-chain
   checks build on signing practices never exercised end-to-end.

6. **Nightly chaos suite on real infra — NOT DONE (risk: MEDIUM).**
   Close: run `.github/workflows/nightly-chaos.yml` slow failure-injection
   against real Redis/Postgres (currently unit-level only). Task 3 scaling
   and Task 5 operational maturity depend on failure behavior never observed.

7. **Independent JA4S verification — NOT DONE (risk: LOW).**
   Close: cross-check JA4S vectors against an independent implementation
   (current vectors are self-derived; spec text is diagram-only, labeled
   EXPERIMENTAL). Affects Task 1 field-reference accuracy for fingerprints.

8. **PQ interop against real hybrid servers — NOT DONE (risk: LOW).**
   Close: captures against servers negotiating hybrid PQ groups
   (X25519MLKEM768 etc.). Classification code exists but has zero live
   observations; posture reporting (Task 6-adjacent analytics) is ungrounded.

9. **v1.0 (or 0.4.0-RC) tag by owner — NOT DONE (risk: HIGH, process).**
   Close: owner reviews `docs/v1-readiness.md`, tags the release. Phase 5
   migrations must be tested "on a populated database from the oldest
   supported release" — with no tagged release, there is no defined oldest
   supported release, so upgrade/rollback testing has no baseline.

10. **No issue/feedback corpus for prioritization — EMPTY (risk: HIGH).**
    Close: file pilot issues (or export tracker issues into the repo) so
    Tasks 1–8 can be ranked by evidence as the prompt requires. With zero
    issues and zero pilot notes, any priority order would be invented.

## Recommendation

Close items 1–2 (pilots + 30-day run) and item 9 (tag a release) first.
Re-run this gate after that. Until then, Phase 5 Tasks 1–8 are **deferred
in full** — per the task brief, no code changes follow this file.
