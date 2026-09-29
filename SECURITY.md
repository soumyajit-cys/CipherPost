# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (Phase 1 foundations onward) | Yes |
| Older snapshots / demo tags | No — upgrade to `main` |

Phase 1 is "secure, clean, and trustworthy foundations" — not a
production-ready claim. See README "Maturity" and THREAT_MODEL.md for honest
scope. If you deploy, track `main` and review SECURITY notes each upgrade.

## Reporting a vulnerability

**Do not open a public issue for suspected vulnerabilities.**

- Email the maintainers privately with: affected commit/branch, steps to
  reproduce (PCAP/config redacted), impact assessment, and your contact.
- Include logs without secrets (redact `JWT_SECRET`, `ADMIN_PASSWORD`,
  `POSTGRES_PASSWORD`, API keys, `Authorization` headers, `?ticket=` values).
- Expect acknowledgement within 5 business days; we will coordinate a fix
  and disclosure timeline with you.
- Safe harbor: good-faith research against your own deployment is welcomed.
  Do not test systems you do not own.

## Scope notes (high-value areas)

- Auth: JWT handling (`backend/app/core/auth.py`), RBAC, API keys, login
  lockout, SSE tickets (`POST /api/v1/live/ticket`), CORS.
- Startup secret enforcement (`CIPHERPOST_ENV`, `validate_startup_secrets`).
- Parser attack surface: `packets.py`, `tls_records.py`, `handshake.py`,
  X.509 handling — untrusted bytes must never crash the worker.
- Secrets handling: `.env` / `k8s/secret.local.yaml` must never be committed;
  CI runs gitleaks + audits.

## After a report

We will: confirm, fix on a private branch, add regression tests, rotate any
exposed sample secrets, and publish a fix commit with credit (if desired).
