# Branch protection (owner must enable in GitHub UI)

CipherPost is pre-1.0 with no branch protection verified. The owner must
enable these settings on `main` (Settings → Branches → Add rule for `main`).
Do NOT attempt to change them from automation; verify with `gh` below.

## Required settings

- Require a pull request before merging (block direct pushes to `main`).
- Require approvals: at least 1 review, dismiss stale reviews on new pushes.
- Require status checks to pass before merging, by exact name:
  - `backend` (fast suite + synthetic evals + real-eval harness + OpenAPI gate)
  - `migrate-check` (empty-Postgres upgrade + `alembic check`)
  - `restore-check` (backup → wipe → restore → row counts)
  - `frontend` (type-check + build + audit)
  - `secrets` (gitleaks scan)
  - `helm` (lint + template + kubeconform)
  - `container-scan` (Trivy image scan)
  - `claims-check` (banned-phrase gate, `scripts/check_claims.py`)
- Require branches to be up to date before merging.
- Block force pushes to `main`; restrict deletions.
- Restrict who can push to `main` (owner/admins only; no direct commits).

## Verify with GitHub CLI (read-only)

```bash
# List protection for main (needs admin:read or owner token)
gh api repos/{owner}/{repo}/branches/main/protection --jq .

# Expected: required_pull_request_reviews, required_status_checks with the
# contexts above, enforce_admins.enabled=true,
# allow_force_pushes.enabled=false, allow_deletions.enabled=false.

# Quick checklist script:
gh api repos/{owner}/{repo}/branches/main/protection \
  --jq '{prs: .required_pull_request_reviews.required_approving_review_count,
         checks: [.required_status_checks.checks[].context],
         enforce_admins: .enforce_admins.enabled,
         force_push: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
```

Last verified: not verified — no GitHub API run recorded. Owner must run the
commands above and paste the output into `docs/evidence/branch-protection.md`
(or attach the run link) before claiming protection is on.
