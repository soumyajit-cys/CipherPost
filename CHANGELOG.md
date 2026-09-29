# Changelog

## Phase 2 — reliability for unattended live traffic (2026-09-30)

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

## Phase 1 — secure, clean, trustworthy foundations (2026-09-29)

Secure-by-default startup, PyJWT + lockout + CORS + SSE tickets, repo hygiene,
pinned deps, Alembic migrations, deployment hardening, real-data eval harness.
