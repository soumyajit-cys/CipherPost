# CipherPost

AI-assisted passive network forensic analysis of email infrastructure cryptography.

CipherPost ingests PCAP captures of SMTP/IMAP/POP3 traffic and produces a
cryptographic security posture assessment: it reconstructs TCP streams from
raw packets, parses TLS handshakes and X.509 certificate chains, applies a
deterministic, auditable rules engine (NIST SP 800-52r2 / OWASP), augments
the findings with an ML-based risk score and SHAP explanations, and emits
prioritized findings in JSON/HTML/PDF plus an interactive React dashboard.

## Architecture

```
                ┌─────────────┐     Redis Streams / Pub/Sub
  PCAP ─────────┤  Replay     ├─────────────────────────────────────┐
  (file)        └──────┬──────┘                                     │
                      │                                            ▼
  Live traffic ───────┤  Capture worker (scapy/AF_PACKET)          │
  (SPAN/TAP,          │  • promiscuous, BPF ports                  │
   promiscuous)       │  • streaming TCP reassembly (5-tuple,      │
                      │    idle timeout, memory caps)               │
                      │  • rolling raw capture (segment files,      │
                      │    auto-purged after window)                │
                      └──────┬──────────────────────────────────────┘
                             │  cipherpost:sessions (XADD)
                             ▼
                      ┌──────────────┐
                      │   Analysis   │──▶ TLS/Handshake + X.509 + Rules (primary, auditable)
                      │   worker     │──▶ ML posture (GradientBoost 0-100) + IsolationForest (rolling 7d baseline) + SHAP
                      └──────┬───────┘
                             │ findings  (cipherpost:findings)
                ┌────────────┼────────────────┐
                ▼            ▼                ▼
           PostgreSQL   Alert dispatcher   SSE pub/sub ──▶ React (live via EventSource)
           (sessions,   (webhook / Slack /  (Live page)
            findings,    syslog CEF /       Recharts, dense SOC aesthetic
            alerts,      email, dedup +     + PCAP import (replay)
            baseline)    rate-limit)
                │            │
                └─────┬──────┘
                      ▼
              FastAPI + Reports (JSON/HTML/PDF, time-window fleet trend)
```

- **Stage 1** — Corpus + lab traffic generator (`scripts/traffic_generator.py`) across TLS matrix (strong/1.2/expired/self-signed/untrusted/STARTTLS-strip)
- **Stage 2** — Live capture daemon: scapy sniff (or pcap replay) → streaming reassembly keyed by 5-tuple → Redis `cipherpost:sessions`
- **Stage 3** — Analysis worker consumes sessions → shared `analyze_session()` (handshake, certs, 19 rules); validated 100% P/R vs corpus
- **Stage 4** — Rolling ML baseline (`FLEET_BASELINE_WINDOW_DAYS=7`, refit every N sessions) + SHAP, published to `cipherpost:findings`
- **Stage 5** — Alert dispatcher (pluggable webhook/slack/syslog/email, threshold/dedup/rate-limit) + SSE live feeds (`/live/*`) + historical queries + live dashboard
- **Stage 6** — Deterministic replay harness, fuzz/load tests, Dockerized full stack, Prometheus `/metrics` + structured logs

## Quick Start (full stack via Docker)

```bash
# Batch + live stack (capture, analyzer, alerter, API, worker, frontend)
docker compose -f docker/docker-compose.yml up --build

# With replay demo (feeds fixtures through live pipeline, no privileges needed)
docker compose -f docker/docker-compose.yml --profile replay up --build
```

- Frontend dashboard: http://localhost:3000 — live feed at `/live`
- API: http://localhost:8000 (docs at http://localhost:8000/docs)
- PostgreSQL: localhost:5432, Redis: localhost:6379
- Prometheus: http://localhost:8000/metrics

### Live capture deployment (SPAN/TAP)

CipherPost is designed to sit behind a **SPAN/mirror port or network TAP**, not on the mail host itself. The capture container must see *other hosts'* traffic.

```yaml
# in docker-compose.yml — capture service
capture:
  network_mode: host      # so the container sees the host's interface
  cap_add: [NET_RAW, NET_ADMIN]   # instead of privileged:true / root
  command: ["python", "-m", "app.live.capture", "--iface", "eth0"]
```

Required Linux capabilities: `CAP_NET_RAW` + `CAP_NET_ADMIN` (or `privileged: true` as a shortcut). No full root required. Configure the interface via `CIPHERPOST_LIVE_IFACE` and the BPF port list via `CIPHERPOST_LIVE_BPF_PORTS` (default `25,587,465,110,995,143,993`). For environments where live network access is unavailable (hackathon judging), use the **replay demo** above or upload a PCAP via the dashboard — the analysis engine is identical.

### Rolling retention & resource limits

- Raw frames are written to time-chunked segment files in `CIPHERPOST_RAW_CAPTURE_DIR` (`/data/capture`). Files older than `CIPHERPOST_RAW_RETENTION_SECONDS` (default 6h, configurable 1–24h) are auto-purged. Sessions store `raw_refs` for forensic replay while within the window; older refs resolve to “purged”.
- Reassembly is bounded: `CIPHERPOST_LIVE_MAX_SESSIONS` (default 4096) concurrent streams, `CIPHERPOST_LIVE_MAX_SESSION_BUFFER_BYTES` per stream (default 512 KiB), `CIPHERPOST_LIVE_IDLE_TIMEOUT` (default 60s). Over-cap streams are finalized with `closed_by=cap/evicted` and counted in `/metrics` and `live/status`, never OOM.

## Local development

```bash
# Backend
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

# Generate corpus + run tests
PYTHONPATH=backend/. python -m app.parsing.generate_corpus tests/fixtures
PYTHONPATH=backend/. python -m pytest backend/tests -q

# Run rules evaluation (precision/recall against labeled corpus)
PYTHONPATH=backend/. python -m app.parsing.eval_rules tests/fixtures

# Run ML evaluation (held-out + rule-vs-ML disagreement report)
PYTHONPATH=backend/. python -m app.ml.eval_ml tests/fixtures
```

## Frontend dashboard

```bash
cd frontend
npm install
npm run dev        # live reload → http://localhost:5173 (proxies /api → :8000)
npm run build      # type-check (tsc -b) + production bundle → dist/
```

The dashboard ships with a **mock API mode on by default**, so it renders
authentic results (generated by the real pipeline via `scripts/export_mock_data.py`)
with **no backend running**. The API layer is a single typed client; the pages
never import the mock or HTTP implementations directly.

| Variable | Default | Effect |
|----------|---------|--------|
| `VITE_API_MODE` | `mock` | `mock` reads local fixtures (`frontend/src/api/mock/data.json`); `http` calls the live backend |
| `VITE_API_BASE_URL` | `/api/v1` | Base path only used in `http` mode |

```bash
# demo without a backend (default)
npm run dev

# live backend
VITE_API_MODE=http VITE_API_BASE_URL=/api/v1 npm run dev   # or set in frontend/.env
```

In `http` mode the client maps the backend's snake_case `/api/v1/*` contract to
the camelCase TypeScript interfaces in `frontend/src/api/types.ts` (jobs list,
upload, sessions, findings, SHAP, fleet, report export). The active mode is shown
in the dashboard header ("fixture data" vs "live backend").

Re-generate the mock fixture after changing fixture corpus or feature logic:

```bash
PYTHONPATH=backend/. python scripts/export_mock_data.py
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/upload` | Upload `.pcap` → create analysis job (also feeds live pipeline in replay mode) |
| GET  | `/api/v1/jobs` | List jobs |
| GET  | `/api/v1/jobs/{id}` | Job status/progress |
| GET  | `/api/v1/jobs/{id}/sessions` | Per-session results |
| GET  | `/api/v1/jobs/{id}/findings` | Findings (severity-sorted) |
| GET  | `/api/v1/jobs/{id}/shap` | SHAP explanations |
| GET  | `/api/v1/jobs/{id}/fleet` | Fleet summary metrics |
| GET  | `/api/v1/jobs/{id}/report.{json\|html\|pdf}` | Report export |
| GET  | `/api/v1/sessions?protocol=&severity=&limit=` | Historical sessions (live+batch, filterable) |
| GET  | `/api/v1/findings?severity=&protocol=` | Historical findings |
| GET  | `/api/v1/fleet/trend?days=7` | Posture trend (live store) |
| GET  | `/api/v1/live/stream` | **SSE** unified live feed (sessions+findings+alerts) |
| GET  | `/api/v1/live/sessions`, `/live/findings`, `/live/alerts` | SSE per channel |
| GET  | `/api/v1/live/status` | Capture stats + queue depths + metrics gossip |
| GET  | `/api/v1/alerts` | Recent dispatched alerts |
| GET/POST | `/api/v1/alerts/config` | Alert channel config (webhook/slack/syslog/email) |
| GET  | `/api/v1/health`, `/metrics` | Health + Prometheus metrics |
| Webhook | `POST {ALERT_WEBHOOK_URL}` | Real-time alert (threshold `ALERT_MIN_SEVERITY`, dedup window, rate-limit) |

## Methodology notes

- The **deterministic rules engine is the primary detection layer** — auditable,
  references NIST SP 800-52r2 / OWASP / RFCs. ML augments it, never replaces it.
- ML labels initially derive from the rules engine on the labeled corpus; this
  limitation is documented and surfaced to users via SHAP values and an explicit
  rule-vs-ML disagreement report.
- Certificate chain validation uses a configured trust store
  (`CIPHERPOST_TRUSTED_CA_BUNDLE_PATH`, default `tests/fixtures/trusted_root.pem`).

## Project layout

```
backend/app/
  core/       config, database, logging
  models/     SQLAlchemy entities
  parsing/    reassembly, TLS parsing, certs, rules, analysis, corpus gen, eval
  ml/         features, ML engine, eval
  reporting/  JSON/HTML/PDF report generator
  api/        FastAPI application
  services/   Celery worker tasks
frontend/     React + Recharts dashboard
docker/       Dockerfiles, docker-compose, nginx
tests/        corpus fixtures + integration/robustness suites
```
