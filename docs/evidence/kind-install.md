# Item 4 evidence: Helm chart install test (2026-10-05)

Result: **NOT-VERIFIED** (workflow written-but-not-run).

## Why not run

- Lab host has no `kind`, `kubectl`, or `helm` binaries, no Docker daemon
  (`docker info` fails), and no workflow execution is available from here.
- Per evidence rules: PASS requires a real green workflow run or a local run
  log. Neither exists. The workflow file is validated only by YAML parse.

## What was delivered

- `.github/workflows/kind-install.yml` (12 steps): pinned kind v0.24.0 +
  helm v4.0.0, kind cluster with a capture-labeled worker, image builds from
  `docker/Dockerfile.{api,worker,frontend}`, `kind load`, eval secrets
  (never in values), install with bundled Postgres/Redis, migrate-Job wait,
  rollout waits, smoke test (liveness, readiness, bootstrap-admin login,
  fixture upload, job COMPLETED, findings > 0), `helm upgrade`
  (replicas 3) + `helm rollback`, log artifacts always.
- Chart fixes from read-only review (no install exposed them; each is
  independently unambiguous):
  1. `templates/migrate-job.yaml` (new): single pre-install/pre-upgrade
     hook Job honoring `migration.backoffLimit`; `templates/backend.yaml`:
     removed 2× duplicated racing initContainers. Also matches NOTES.txt,
     which already promised a migrate Job that did not exist.
  2. `templates/bundled.yaml`: removed stray `---` producing an empty doc.
  3. `templates/validations.yaml` (new): fail-fast `fail` when neither
     bundled nor external DB/Redis is configured (previously: crash-looping
     pods). Chart defaults intentionally no longer template; CI updated to
     template with bundled deps plus a negative test asserting the failure.
- Remaining chart gaps NOT fixed here (documented, need install proof):
  registry-qualified images/pull secrets, analyzer HPA min/max mismatch,
  probe tuning (initialDelay/failureThreshold), bundled Redis auth/persistence,
  StatefulSet storageClassName, resource/securityContext parity for bundled
  pods. None were changed without the ability to verify.

## What the owner must do

Run the workflow (push touching `deploy/helm/cipherpost/**` triggers it, or
`workflow_dispatch`), or `kind create cluster` locally per the workflow
steps, and attach the run link/log here. Only then does this item become
PASS. Until then the v1-readiness kind line stays NOT-VERIFIED.
