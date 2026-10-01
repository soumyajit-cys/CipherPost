# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic; `backend/app/VERSION` is the single source of truth.

## [Unreleased]

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
