# Security review pack (facts only, linked to code/config)

For a pilot organization's security team. Every claim links to the enforcing
code or config; anything not yet verified is labeled as such.

## Architecture and data flows

- Sensor (capture agent, `backend/app/agent/` or `app.live.capture`) sniffs
  mail ports via SPAN/TAP → reassembles TCP (`app/live/reassembly.py`) →
  parses TLS/X.509 locally (`app/parsing/`) → ships **metadata only** to
  `POST /api/v1/ingest/sessions` (agent token `X-Agent-Token`, gzip, 429
  backpressure). Privacy allow-list: `app/agent/meta.py:PRIVACY_ALLOW_LIST`;
  no-payload test: `test_phase3_agent.py::test_no_payload_bytes_leave_sensor`.
- Server: FastAPI (`backend/app/api/main.py`) + Celery + analysis workers
  (Redis streams, at-least-once with DLQ: `app/live/streams.py`) + alert
  dispatcher (webhook/Slack/CEF/Splunk/email + Jira).
- Storage: Postgres (sessions, findings, certs, flows, alerts, audit,
  suppressions, feedback). Redis is transport only (streams + heartbeats).

## What data is stored (and where)

| Data | Where | Retention |
|---|---|---|
| Raw frames | sensor `/data/capture` segments only | rolling `RAW_RETENTION_SECONDS` (6 h), never backed up |
| Session metadata (5-tuple, TLS facts) | Postgres `sessions` | `RETENTION_SESSIONS_DAYS` (90) |
| Findings / SHAP | Postgres `findings`, `shap_rows` | `RETENTION_FINDINGS_DAYS` (90) |
| Alerts + per-channel delivery | Postgres `alerts`, `alert_deliveries` | `RETENTION_ALERTS_DAYS` (180) |
| Audit log | Postgres `audit_log` | `RETENTION_AUDIT_DAYS` (365, longest) |
| Legal holds survive all purges (`legal_hold` flags, audited). |

## Encryption

- In transit: TLS to the API/ingest (operator-provided reverse proxy or
  ingress cert); agent supports custom CA bundle + SPKI pinning
  (`app/agent/shipper.py`).
- At rest: Postgres volume encryption is the operator's (managed DB
  recommended); API keys/agent tokens stored as SHA-256 hashes only
  (`app/core/auth.py`); TOTP secrets AES-GCM encrypted
  (`app/core/mfa.py`); recovery codes hashed.

## Auth model

- Local users: PBKDF2-HMAC-SHA256 (200k), login lockout, optional TOTP MFA
  with brute-force guard, session versioning + jti deny-list.
- SSO: OIDC code+PKCE, RS256 pinned, JWKS rotation, iss/aud/exp/nonce
  enforced; JIT provisioning optional; break-glass disabled by default.
- Agents: org-scoped `cpat_` tokens (hashed, revocable, expirable).
- RBAC: auditor < analyst < admin; platform admins manage orgs but read
  tenant data only via audited assume-tokens (1 h TTL).

## Tenancy model

One `org_id` per row, filtered on every query path (A/B suite:
`test_phase3_isolation.py`); cross-org access by ID is 404. Direct-Redis
mode is single-tenant only; remote sensors use HTTPS ingest. Full statement:
`THREAT_MODEL.md` §5.

## Logging

Structured logs (structlog) + audit log for: logins/failures/MFA/SSO
provisioning/role changes/suppressions/holds/assume/token lifecycle/retention
runs. Diagnostics bundles redact secrets and mask addresses by default.

## Residual scope (not verified here)

No 30-day live run; no kind-cluster install test; real-IdP SSO tested
Keycloak-26.8.0-only (`docs/evidence/sso-keycloak.md`); synthetic + 28-capture
lab precision only. Compliance tags load from versioned `mapping-v1.json`
(each tag carries framework title, control, and source URL; re-check current
framework editions during audits). See README Maturity.

Last verified: 2026-10-05 — architecture/data-flow statements against the
committed code and configs listed above; SSO scope Keycloak 26.8.0 only
(`docs/evidence/sso-keycloak.md`); compliance tags are versioned-data
mappings (`mapping-v1.json`), not an auditor certification; MTA-STS/DANE
behavior per unit/fake-DNS tests only (no live resolver run).
