# CipherPost Deployment Guide

Three supported shapes, in order of operational weight.

## Shape A — Single host, docker-compose (demo / small deployment)

```bash
cp .env.example .env   # fill in secrets first (POSTGRES_PASSWORD, JWT_SECRET, ADMIN_PASSWORD)
POSTGRES_PASSWORD=strong-dev-only docker compose -f docker/docker-compose.yml up --build
# replay demo (no capture privileges needed):
docker compose -f docker/docker-compose.yml --profile replay up --build
```

- Dashboard http://host:3000 (`/` landing, `/app` console, `/app/live` feed).
- API http://host:8000/docs. Postgres/Redis are **internal only** (no published
  ports). For local debugging use `docker compose run --rm db psql -U cipherpost`
  or temporarily add `127.0.0.1:5432:5432`.
- DB password comes from `POSTGRES_PASSWORD` env (`.env`), never hardcoded;
  all `CIPHERPOST_DATABASE_URL*` values template from it.
- `migrate` service runs `python -m app.migrate` (Alembic to head) before `api`
  starts (`service_completed_successfully`); API also runs migrations on startup
  with `create_all` fallback for SQLite/tests.
- All Python containers run as non-root `appuser (10001)`; `capture` adds only
  `NET_RAW, NET_ADMIN` via `cap_add`, never `privileged` / root.
- Good for: evaluation, single mail gateway, archived-PCAP forensics.
- Limits: one capture worker, one interface, in-host Postgres/Redis.
- Local compose sets `CIPHERPOST_ENV=dev` (ephemeral JWT + warning). Production
  must use `production` (default) with strong secrets or the API refuses to start.

## Shape B — SPAN/TAP distributed capture (enterprise)

1. Mirror the mail VLAN(s) to sensor NICs (SPAN session or TAP aggregator).
2. On each sensor host, run the capture agent with host networking as non-root:
   ```yaml
   # docker-compose override
   capture:
     user: "10001:10001"
     network_mode: host
     cap_add: [NET_RAW, NET_ADMIN]   # never privileged:true / root
     environment:
       CIPHERPOST_AGENT_ID: "site-dc1/span-mail"
       CIPHERPOST_LIVE_IFACE: eth1
   ```
   Or one agent per segment — all report to the same Redis/API.
3. Centralize: one Postgres (managed preferred), one Redis, N analyzers
   (consumer groups prevent double-processing), one alerter.
4. Verify coverage in the dashboard: `GET /api/v1/agents` must show every
   site agent `online`, and `/api/v1/live/status` queues near zero.
5. Put TLS (reverse proxy) in front of :8000/:3000 — JWT/SSE tokens are
   bearer secrets.

## Shape C — Kubernetes (scaled enterprise)

```bash
kubectl apply -f k8s/namespace.yaml
cp k8s/secret.yaml k8s/secret.local.yaml  # fill in (gitignored)
kubectl apply -f k8s/secret.local.yaml
kubectl apply -f k8s/configmap.yaml k8s/postgres-redis.yaml
kubectl apply -f k8s/backend.yaml k8s/frontend.yaml
kubectl label node <span-node> cipherpost/capture=true
kubectl apply -f k8s/capture-daemonset.yaml
```

- Images `cipherpost/{api,worker,frontend}:latest` built from `docker/`
  (Python images run as `appuser 10001`; capture DaemonSet adds only
  `NET_RAW, NET_ADMIN`, `runAsNonRoot: true`, never privileged).
- API Deployments use a `migrate` initContainer (`python -m app.migrate`) so
  Postgres is at Alembic head before the server starts.
- Analyzer HPA (2–10 replicas) on CPU; also watch `queues.sessions`.
- Small clusters may keep in-cluster Postgres/Redis; production should use
  managed database/cache and point the Secret at them.
- Resource starting points are in the manifests (per-component
  requests/limits with throughput assumptions in comments).

## Secrets

- Never commit `.env` (it was tracked historically with dev-only values —
  if you cloned before the fix, **rotate** `POSTGRES_PASSWORD`,
  `JWT_SECRET`, and `ADMIN_PASSWORD`; the old values were local-dev only).
- Production refuses to start unless `CIPHERPOST_JWT_SECRET` is ≥ 32 random
  bytes and `CIPHERPOST_ADMIN_PASSWORD` is ≥ 12 chars (no `change-me`/`CHANGEME`).
  Generate with `openssl rand -hex 32`. `CIPHERPOST_ENV=dev` is local-only.
- Compose reads `POSTGRES_PASSWORD` from `.env`; K8s reads it from
  `secret.local.yaml` (gitignored template `secret.yaml`).
- Auth hardening: PyJWT HS256 pinned, login lockout (5/5min per account,
  20/5min per IP, generic 401, `auth.login.failed` audited), CORS allowlist
  via `CIPHERPOST_CORS_ORIGINS` (default same-origin), SSE via
  `POST /api/v1/live/ticket` (60s single-use) — never put main tokens in URLs.
- Use `.env.example` / `k8s/secret.local.yaml` as the template.
- Pre-commit (`pre-commit install`) + CI gitleaks block new leaks.

## Backup & disaster recovery

- Nightly: `scripts/backup_postgres.sh /backups/cipherpost` (cron/systemd
  timer; keeps 14 dumps; `PG*` env for host/user).
- Restore: `scripts/restore_postgres.sh [--yes] <file.dump>` (asks for the DB
  name unless `--yes`; CI `restore-check` proves backup → wipe → restore keeps
  row counts with Alembic at head).
- RPO/RTO note: dumps cover findings/sessions/history (the long-term
  asset). Raw capture segments are rolling-window by design and are NOT
  backed up. For point-in-time recovery, enable Postgres WAL archiving.
- Redis streams are transport, not storage — safe to lose on failover
  (consumers reclaim via XAUTOCLAIM; in-flight sessions re-derive; poison
  messages sit in `<stream>:dlq`, never silently dropped).

## Data lifecycle (Phase 2)

- Per-type retention (days, `0` = keep): `RETENTION_SESSIONS_DAYS` (90),
  `RETENTION_FINDINGS_DAYS` (90), `RETENTION_ALERTS_DAYS` (180),
  `RETENTION_AUDIT_DAYS` (365, longest). Raw capture still uses
  `RAW_RETENTION_SECONDS` + `RetentionRawStore` purge.
- Run `python -m app.live.retention` hourly (cron/K8s CronJob): batched
  deletes (`RETENTION_BATCH_SIZE`), legal-hold rows skipped, purged-row
  metrics exposed for Prometheus.
- Legal hold: `POST /api/v1/jobs/{id}/legal-hold` and
  `POST /api/v1/findings/{id}/legal-hold` (audited); held rows survive purges.

## Transport checks (Phase 2)

- Set `CIPHERPOST_DNS_RESOLVER` (e.g. your validating resolver IP),
  `CIPHERPOST_DNS_TIMEOUT_SECONDS`, and `CIPHERPOST_DNSSEC_TRUST_ANCHOR`
  (base64 DNSKEY DER) to enable real MTA-STS/DANE. Without an anchor, signed
  TLSA validates as `dnssec-failed` (honest: trust cannot be established).
- `GET /api/v1/domains/{d}/transport-security?refresh=true` for on-demand
  re-checks; the alerter re-checks seen domains every
  `TRANSPORT_RECHECK_INTERVAL_SECONDS` (alerts only on proven `misconfigured`).
- Optional live smoke: `python scripts/smoke_transport.py gmail.com` (needs
  internet; never in CI).

## First-boot checklist

1. Secrets set (`JWT_SECRET` ≥ 32 random chars e.g. `openssl rand -hex 32`,
   strong `ADMIN_PASSWORD` ≥ 12 chars, `POSTGRES_PASSWORD` in env/secret;
   `CIPHERPOST_ENV=production` default enforces this at startup).
2. Migrations applied (`python -m app.migrate` / compose `migrate` service /
   K8s initContainer; CI verifies `alembic check` with no drift).
2. Login as bootstrap admin → create operator accounts → rotate/disable
   bootstrap if policy requires.
3. Configure alert channels (admin only) + Splunk HEC / Jira if used.
4. Set `CERT_EXPIRY_WARN_DAYS`, verify `/api/v1/certs/expiring`.
5. Import Grafana dashboard (`ops/grafana/dashboard.json`) against
   Prometheus scraping `/metrics`.
