# Runbook — CipherPost alerts

For each Prometheus alert in `ops/prometheus/alerts.yml`: what it means, how
to confirm, how to fix. Check `/api/v1/health` and `/api/v1/live/status`
first for every incident (queues, DLQ depths, drops).

## Capture-dropping (CipherPostCaptureDropping)

- Means: capture's bounded publish buffer overflowed (`sessions_dropped_total{reason="buffer-full"}`)
  or reassembly evicted streams (`sessions_dropped`); Redis was unreachable or
  traffic exceeded caps.
- Confirm: `/api/v1/live/status` → metrics `sessions_dropped*`; capture logs
  `publish session failed`; `redis-cli ping`.
- Fix: restore Redis; if sustained load, raise `LIVE_MAX_SESSIONS` /
  `CAPTURE_PUBLISH_BUFFER` or add sensor hosts; drops are counted, never silent.

## Consumer-lag (CipherPostConsumerLagGrowing)

- Means: `cipherpost:sessions` stream length > 1000 for 10m — analyzers behind.
- Confirm: `/api/v1/live/status` queues.sessions; analyzer HPA status; analyzer logs.
- Fix: scale analyzers (HPA 2–10 or manual replicas); check Postgres slowness
  (analyzer `_persist` blocks); unacked-but-processed entries are reclaimed via
  XAUTOCLAIM — no manual ACK needed.

## Dead-letter (CipherPostDeadLetterNonEmpty)

- Means: poison messages exhausted `STREAM_MAX_ATTEMPTS` and sit in `<stream>:dlq`.
- Confirm: `/api/v1/live/status` → `dlq` depths; inspect entries:
  `redis-cli XRANGE cipherpost:sessions:dlq - + COUNT 5` (payload + error + attempts).
- Fix: fix the parser/handler bug (payload is preserved), redeploy, then
  replay the entry (XADD back to the main stream) or discard (XDEL). Never
  delete without reading the error field.

## No-sessions (CipherPostNoSessions)

- Means: no sessions emitted in 15m — sensor blind or mail idle.
- Confirm: `/api/v1/agents` online? capture logs (permission denied →
  needs `cap_add: [NET_RAW, NET_ADMIN]` + host network); SPAN session active?
- Fix: restore mirror/TAP, restart capture; legitimate idle windows should
  scope this alert's `for:` longer.

## Delivery-failures (CipherPostAlertDeliveryFailures)

- Means: one or more alert channels failing (`alert_deliveries` rows with
  status failed, or `alerts_failed` counter rising). Other channels still send.
- Confirm: query `alert_deliveries` for `last_error`; test webhook/SMTP creds.
- Fix: fix the channel config (`/api/v1/alerts/config`, admin); failed
  deliveries are recorded per channel and retried once — no resend needed for
  already-sent channels.

## DB/Redis-down (CipherPostDBDown)

- Means: API unreachable; `/api/v1/health` reports `db_ok`/`redis_ok` false.
- Confirm: `pg_isready`, `redis-cli ping`; `/api/v1/health/ready` (503 + detail).
- Fix: restore backing services; workers buffer (capture) and retry with
  backoff — verify `publish_buffer_depth` drains after recovery. Redis streams
  are transport: in-flight sessions re-derive; Postgres is the durable asset
  (restore via `scripts/restore_postgres.sh`).

## Cert-expiry (CipherPostCertExpiryForecast)

- Means: tracked certificates expiring within `CERT_EXPIRY_WARN_DAYS`.
- Confirm: `GET /api/v1/certs/expiring?days=30`.
- Fix: rotate the cert; alerts dedup for 24h per fingerprint (`expiry_alerted_at`).

## Feature-drift (CipherPostFeatureDrift)

- Means: feature-distribution PSI > 0.5 for 15m — either a real network
  change (new mail cluster, TLS policy rollout) or a data-quality problem
  (parser regression, clock skew).
- Confirm: `GET /api/v1/ml/drift` shows per-feature PSI/z sorted worst-first;
  compare `psi` leaders against recent change windows.
- Fix: for real traffic shifts, retrain baselines (`POST /api/v1/ml/retrain`);
  for parser regressions, fix the parser and re-run the corpus eval.
