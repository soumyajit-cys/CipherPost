# Pilot data-handling summary (facts only, linked to code/config)

For the pilot's security team. Every statement below links to the enforcing
code or config. Anything not verified is marked. This file makes no claims
about deployments we do not operate.

## What is stored, and where

| Data | Where | Default retention |
|---|---|---|
| Raw packet frames | capture host only, `RAW_CAPTURE_DIR` (`/data/capture`) segment files (`backend/app/live/retention.py::RollingRawStore`) | `RAW_RETENTION_SECONDS` = 6 h rolling purge (`backend/app/core/config.py`) |
| Session metadata (5-tuple, TLS facts, fingerprints) | Postgres `sessions` (`backend/app/models/entities.py`) | `RETENTION_SESSIONS_DAYS` = 90 |
| Findings + SHAP rows | Postgres `findings`, `shap_rows` | `RETENTION_FINDINGS_DAYS` = 90 |
| Alerts + per-channel deliveries | Postgres `alerts`, `alert_deliveries` | `RETENTION_ALERTS_DAYS` = 180 |
| Audit log | Postgres `audit_log` | `RETENTION_AUDIT_DAYS` = 365 |
| Redis | transport only (streams, heartbeats) — safe to lose on failover (`DEPLOYMENT.md` Backup & DR) | n/a |

Mail content is **never stored**: the parser reads TLS handshake and
protocol framing; no message bodies, attachments, or credentials are
persisted by the server (`backend/app/parsing/` — no body fields exist on
any model).

## What leaves the sensor

- Remote agents ship **metadata only**, gated by an explicit allow-list:
  `backend/app/agent/meta.py::PRIVACY_ALLOW_LIST` ("exactly what may leave
  the sensor in an ingest message"). Address redaction modes `full |
  truncated | hashed` are applied before shipping (`redact_host`, same file;
  agent config `addr_mode` in `backend/app/agent/agent.py`).
- Verified by `backend/tests/test_phase3_agent.py::test_no_payload_bytes_leave_sensor`.
- Raw frames are never shipped: they stay on the capture host and are purged
  by the rolling window above.

## Retention operation

- `python -m app.live.retention` (hourly cron/CronJob) deletes expired rows
  in batches; `legal_hold` rows survive every purge
  (`backend/app/live/retention.py` — "Never touches rows with legal_hold
  set"); purge counters are exposed as metrics.
- Legal hold is opt-in per job/finding via the audited API endpoints
  (`POST /api/v1/jobs/{id}/legal-hold`, `POST /api/v1/findings/{id}/legal-hold`).

## Encryption

- **In transit (API/ingest)**: operator-provided TLS termination (reverse
  proxy or ingress). Agents support a custom CA bundle and SHA-256 SPKI
  pinning (`backend/app/agent/shipper.py`, `_spki_pin`); a 401 from a
  revoked/rotated token stops the agent.
- **At rest**: Postgres volume encryption is the deployment operator's
  responsibility (managed DB recommended — `docs/security-review-pack.md`);
  CipherPost does not ship storage encryption itself. API keys and agent
  tokens are stored as SHA-256 hashes only (`backend/app/core/auth.py`);
  TOTP secrets are AES-GCM encrypted (`backend/app/core/mfa.py`);
  recovery codes are hashed.

## Who can access

- Local RBAC: auditor < analyst < admin (`backend/app/core/auth.py`).
- Every data row is org-scoped and filtered on every query path
  (isolation suite: `backend/tests/test_phase3_isolation.py`).
- SSO: OIDC code+PKCE, RS256 pinned, JWKS rotation
  (`backend/app/core/oidc.py`; verified Keycloak 26.8.0 only —
  `docs/evidence/sso-keycloak.md`).
- Platform administrators read tenant data only via audited 1-hour
  assume-tokens (`POST /api/v1/admin/assume`; audited in `audit_log`).
- Sensors authenticate with org-scoped `cpat_` tokens (hashed, revocable,
  expirable — `backend/app/models/entities.py::AgentToken`); a session's
  org is stamped from the token, never chosen by the agent.

## Pseudonymization options (operator-selected)

| Mode | Effect on stored/shipped addresses | Where |
|---|---|---|
| `full` | addresses as seen | default in agent config |
| `truncated` | `/24` network address | `redact_host(mode="truncated")` |
| `hashed` | SHA-256 hex digest of the host | `redact_host(mode="hashed")` |

Reports and issue bundles are address-free by default regardless of mode:
`scripts/live_report.py` prints counts/distributions only, and
`scripts/export_issue_bundle.py` masks addresses through the same helper
the diagnostics bundle uses (`app.api.main._mask_addresses`).

## How to delete everything

1. **Normal expiry**: retention runs purge sessions/findings/alerts/audit
   per the table above; raw frames are purged continuously by the rolling
   window. Legal-held rows must be un-held first (audited).
2. **Immediate, per org**: delete the org's rows
   (`retention.py::purge_all` paths) — the pilot's data never co-mingles
   with other orgs' rows.
3. **Total deletion**: stop the stack, drop the Postgres database, delete
   the named volumes (`docker compose down -v`), and delete the capture
   host's `RAW_CAPTURE_DIR` + upload/report directories
   (`UPLOAD_DIR`, `REPORTS_DIR`, `BLOB_DIR`, `MODELS_DIR` in
   `backend/app/core/config.py`). Redis holds only transport state and
   expires with the containers.
4. **Backups**: dumps taken by `scripts/backup_postgres.sh` must be deleted
   separately (they are outside the database); note the retention of the
   backup directory in the pilot record at exit.

Not verified here: volume-level encryption at rest (operator's choice),
any managed-service behavior, and anything about networks we do not
operate. See `docs/security-review-pack.md` "Residual scope".
