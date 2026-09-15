# CipherPost Deployment Guide

Three supported shapes, in order of operational weight.

## Shape A — Single host, docker-compose (demo / small deployment)

```bash
cp .env.example .env   # fill in secrets first
docker compose -f docker/docker-compose.yml up --build
# replay demo (no capture privileges needed):
docker compose -f docker/docker-compose.yml --profile replay up --build
```

- Dashboard http://host:3000 (`/` landing, `/app` console, `/app/live` feed).
- API http://host:8000/docs. Postgres/Redis on 5432/6379.
- Good for: evaluation, single mail gateway, archived-PCAP forensics.
- Limits: one capture worker, one interface, in-host Postgres/Redis.

## Shape B — SPAN/TAP distributed capture (enterprise)

1. Mirror the mail VLAN(s) to sensor NICs (SPAN session or TAP aggregator).
2. On each sensor host, run the capture agent with host networking:
   ```yaml
   # docker-compose override
   capture:
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

- Images `cipherpost/{api,worker,frontend}:latest` built from `docker/`.
- Analyzer HPA (2–10 replicas) on CPU; also watch `queues.sessions`.
- Small clusters may keep in-cluster Postgres/Redis; production should use
  managed database/cache and point the Secret at them.
- Resource starting points are in the manifests (per-component
  requests/limits with throughput assumptions in comments).

## Secrets

- Never commit `.env` (it was tracked historically with dev-only values —
  if you cloned before the fix, **rotate** `POSTGRES_PASSWORD`,
  `JWT_SECRET`, and `ADMIN_PASSWORD`; the old values were local-dev only).
- Use `.env.example` / `k8s/secret.local.yaml` as the template.
- Pre-commit (`pre-commit install`) + CI gitleaks block new leaks.

## Backup & disaster recovery

- Nightly: `scripts/backup_postgres.sh /backups/cipherpost` (cron/systemd
  timer; keeps 14 dumps; `PG*` env for host/user).
- Restore: `scripts/backup_postgres.sh restore <file.dump>`.
- RPO/RTO note: dumps cover findings/sessions/history (the long-term
  asset). Raw capture segments are rolling-window by design and are NOT
  backed up. For point-in-time recovery, enable Postgres WAL archiving.
- Redis streams are transport, not storage — safe to lose on failover
  (capture agents resume; in-flight sessions re-derive).

## First-boot checklist

1. Secrets set (`JWT_SECRET` ≥ 32 random chars, strong `ADMIN_PASSWORD`).
2. Login as bootstrap admin → create operator accounts → rotate/disable
   bootstrap if policy requires.
3. Configure alert channels (admin only) + Splunk HEC / Jira if used.
4. Set `CERT_EXPIRY_WARN_DAYS`, verify `/api/v1/certs/expiring`.
5. Import Grafana dashboard (`ops/grafana/dashboard.json`) against
   Prometheus scraping `/metrics`.
