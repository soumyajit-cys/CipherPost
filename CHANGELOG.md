# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic; `backend/app/VERSION` is the single source of truth.

## [Unreleased]

### Compliance and evidence (Phase 4 task 6)

- Compliance tags load from versioned data (`mapping-v1.json`,
  `mapping_version == 1`, exposed on `/api/v1/compliance/summary`); all
  Phase 4 rules mapped with framework provenance on every tag.
- Hash-chained evidence bundles (`manifest` + `records`, tamper-detected)
  via `cipherpost evidence` and `GET /api/v1/jobs/{id}/evidence`;
  unobservable items labeled, never filled in.

### v1.0 gate (Phase 4 task 8 — NOT READY)

- `docs/v1-readiness.md`: honest gate assessment. Phase 4 ships as 0.4.0-RC
  material; v1.0 is blocked on external pilots, a 30-day live run, kind
  install, real-IdP SSO, and registry/sign verification (all listed, none
  claimed).

### Alert quality (Phase 4 task 5 — measured, no unjustified severity changes)

- Per-rule precision (analyst labels only; null without labels), alert volume,
  time-to-acknowledge, and suppression counts at `GET /api/v1/alerts/quality`
  plus a dashboard page. High-volume rules without labels are flagged
  `needs_review`, never auto-downgraded: with no pilot label data in the repo,
  changing severities would be intuition, not evidence. No rule severities
  were changed in this phase for that reason.
- Ownership routing (rule/host/domain → owner/channel), per-org severity
  policy, digest mode (daily/weekly), and quiet hours (critical always
  bypasses) in the dispatcher; `GET /api/v1/alerts/{id}/explain` with rule
  rationale, exact evidence, and remediation snippets only where verified
  from official docs (Postfix TLS_README, retrieved 2026-10-02).

## [0.3.0] - 2026-10-02 (Phase 3: adoption by outside organizations — in progress)

### Added (Phase 3 workstream — each item tested, see report)

- SSO (OIDC code+PKCE, pinned RS256, JWKS rotation, claim mapping, JIT),
  TOTP MFA (encrypted secrets, recovery codes, lockout), session revocation
  (jti deny-list + versioned tokens), break-glass admin path (`docs/sso.md`).
- Real multi-tenancy: org-scoped agent tokens, HTTPS ingest with org stamping
  and 429 backpressure, platform-vs-org admin split with audited assume-access,
  A/B isolation suite over every org-scoped endpoint.
- Standalone `cipherpost-agent`: local parse, metadata-only shipping (tested),
  disk queue, TLS pinning, health endpoint, container + systemd packaging.
- Offline `cipherpost` CLI (`scan`/`verify-domain`/`rules`/`version`),
  versioned JSON + SARIF, exit codes 0/1/2/3, baseline/suppression filters
  (`docs/cli.md`); `pyproject.toml` packaging (not published).
- Helm chart (`helm lint` + `template` + kubeconform 13/13; no kind run),
  hardened prod compose, upgrade/rollback guide.
- Committed OpenAPI + breaking-change CI gate; API policy (pagination aliases,
  Retry-After, deprecation); SDKs extended and contract-tested vs the schema.
- Release workflow (dry-run safe), SBOM/scan/sign/provenance gates, scan
  allowlist with justifications, licensing decision left to owner,
  contributing/community files.
- Diagnostics bundles (redacted), analyst feedback labels + precision
  dashboard + export, pilot/security/telemetry docs.

## [0.2.0] - 2026-09-30 (Phase 2: reliability for unattended live traffic)

**Reliable delivery:** Redis consumers are at-least-once (ACK after durable
write, idempotent session ids, XAUTOCLAIM reclaim, dead-letter streams with
depth metrics). Capture publishes through a bounded buffer with backoff+jitter
(drop-oldest counted, never blocks sniffing).

**Shared alert state:** dedup and rate budgets in Redis (shared across
restarts/replicas, loud in-memory fallback); per-channel delivery with retry
and `alert_deliveries` status rows; findings grouped by root cause with
occurrence counts.

**Suppressions:** accepted-risk exceptions (`suppressions` table + API +
dashboard) with CIDR/wildcard scope matching, mandatory expiry, RBAC approval,
and audit trail. Suppressed findings stay visible but skip alerts/tickets and
count as accepted risk in compliance.

**Data lifecycle:** per-type retention (raw/sessions/findings/alerts/audit)
with batched purges and metrics; legal-hold flags on jobs/findings;
`scripts/restore_postgres.sh` + CI backup→wipe→restore verification.

**Real MTA-STS/DANE:** dnspython checks with TTL cache, anchor-pinned DNSSEC
(unsigned never counts as DANE), SSRF-safe policy fetch, proven-mismatch
findings, on-demand + scheduled re-checks.

**Mail flows:** per-pair posture aggregation, TLS/plaintext regression
detection feeding the alert pipeline, `/api/v1/flows` + history + CSV,
dashboard page.

**Observability:** health reflects DB/Redis/lag/DLQ/drops/migrations;
liveness/readiness probes; Prometheus rules + runbook; measured sizing guide.

**Validation:** failure-injection suite (nightly CI) + soak script. 128 fast
tests pass; 6 slow chaos tests pass. See README Maturity for honest limits —
a real 30-day live-traffic run is still required before production-ready.

## [0.1.0] - 2026-09-29 (Phase 1: secure, clean, trustworthy foundations)

Secure-by-default startup, PyJWT + lockout + CORS + SSE tickets, repo hygiene,
pinned deps, Alembic migrations, deployment hardening, real-data eval harness.
