# Item 7 evidence: release dry run, no publishing (2026-10-05)

Result: **workflow validated by parse only; push/sign/provenance/registry
NOT-VERIFIED.** No tags created, nothing published.

## What changed

`.github/workflows/release.yml` gained explicit `workflow_dispatch` inputs:

- `dry_run` (default `true`): build, test, scan, SBOM only.
- `enable_push` (default `false`): owner-only path to push+sign from a
  dispatch (still needs `REGISTRY_USER`/`REGISTRY_PASSWORD`/`COSIGN_KEY`
  secrets).

Push condition is now
`(tag-push AND secrets AND dry_run != true) OR (enable_push AND secrets)`.
Verified by reading: real tag pushes behave exactly as before (on push/PR
events `inputs.*` is null, so the first clause reduces to the old
tag+secrets gate); default dispatches can never push; sign/attest steps
still key off the push step's digest output. Pre-release tags (`v0.9.0-rc1`)
match `tags: ["v*"]` and must equal `backend/app/VERSION` (existing
verify-tag job, unchanged).

## What was validated vs not

- Validated: YAML parses (`python -c yaml.safe_load`); condition logic
  re-derived above; SBOM/scan steps run on PRs and dispatches by construction.
- NOT validated (no runner, no daemon, no actionlint/cosign locally):
  `docker buildx` multi-arch builds, Trivy/SBOM action runs, cosign keyless
  signing, attestations, registry push. `actionlint` not installed; YAML
  checked by parse only — say so plainly.

## Owner runbook (to run the real thing)

1. Set repo secrets: `REGISTRY_USER`, `REGISTRY_PASSWORD` (registry
   credentials), `COSIGN_KEY` (only if signing with a key instead of
   keyless OIDC).
2. For a dry run: Actions → cipherpost-release → Run workflow (defaults:
   dry_run=true). Expect green build/test/scan/SBOM artifacts, no push.
3. For a pre-release: set `backend/app/VERSION` to e.g. `0.9.0-rc1`, update
   CHANGELOG, push tag `v0.9.0-rc1`. The tag pipeline verifies VERSION==tag,
   then builds/scans; push/sign run only with secrets present.
4. For a real release: same with a final version tag. Provenance attestations
   require `id-token: write` (already in the workflow).
