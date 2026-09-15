# CipherPost Authentication & Tenancy (Track 1)

**Explicit contract change:** every `/api/v1` route except `/health` and
`/metrics` now requires authentication. Unauthenticated calls get **401**;
under-privileged calls get **403**. Health/metrics stay public so
load-balancers and Prometheus don't need credentials.

## Credentials

- **Dashboard login** → `POST /api/v1/auth/login` returns a short-lived
  HS256 JWT (`CIPHERPOST_JWT_EXPIRY_SECONDS`, default 24h). Send as
  `Authorization: Bearer <token>`. SSE/EventSource can't send headers, so
  live streams also accept `?token=<jwt>`.
- **Programmatic access** → API keys (`cp_<hex>`, created by admins via
  `POST /api/v1/api-keys`; the raw key is shown **once**). Send as
  `X-API-Key` header. Only the SHA-256 hash is stored.

No third-party auth deps: JWT is HMAC-SHA256 and passwords are
PBKDF2-HMAC-SHA256 (200k iterations) in `backend/app/core/auth.py` —
~150 auditable stdlib lines.

## Roles

| role | view | upload | alert config | users/keys | audit log |
|---|---|---|---|---|---|
| admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| analyst | ✓ | ✓ | read | – | – |
| auditor | ✓ | – | – | – | ✓ |

## Tenancy

`org_id` on users, API keys, jobs, sessions, and alerts. All reads filter
by the caller's org. Fresh installs get a `default` org plus a bootstrap
admin (`CIPHERPOST_ADMIN_EMAIL` / `CIPHERPOST_ADMIN_PASSWORD` — change both
immediately). Pre-auth rows are backfilled to the default org at startup.

## Audit

`auth.login`, `pcap.upload`, `report.export`, `user.*`, `apikey.*`,
`alertconfig.update` are written to `audit_log`. Admins and auditors can
read via `GET /api/v1/audit`.

## Production checklist

1. Set `CIPHERPOST_JWT_SECRET` (long random), `CIPHERPOST_ADMIN_PASSWORD`.
2. Create per-operator accounts; disable or rotate the bootstrap admin.
3. Issue scoped API keys per integration (name them, set `expires_days`).
