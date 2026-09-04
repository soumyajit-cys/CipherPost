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
PCAP ──▶ Ingestion ──▶ TCP Reassembly ──▶ TLS Handshake/Cert Parsing
                                              │
                                              ▼
                                        Rules Engine (deterministic, primary)
                                              │
                                              ▼
                              ML Risk Scoring (GradientBoost) + Anomaly (IsolationForest)
                                              │
                                              ▼
                              SHAP Explanations + Reports (JSON/HTML/PDF)
                                              │
                                              ▼
                              FastAPI + Celery + PostgreSQL + React Dashboard
```

- **Stage 1** — Corpus generation: synthetic labeled PCAPs (16 scenarios) + shared trust root
- **Stage 2** — Protocol detection & TCP stream reassembly (SYN-anchored, STARTTLS-aware)
- **Stage 3** — TLS handshake & X.509 certificate analysis + 19 deterministic rules
- **Stage 4** — ML risk scoring (0–100), Isolation Forest anomaly detection, SHAP explainability
- **Stage 5** — Reporting (JSON/HTML/PDF) + FastAPI + Celery + React dashboard
- **Stage 6** — Docker, robustness/fuzz tests, monitoring

## Quick Start (full stack via Docker)

```bash
docker compose -f docker/docker-compose.yml up --build
```

- Frontend dashboard: http://localhost:3000
- API: http://localhost:8000 (docs at http://localhost:8000/docs)
- PostgreSQL: localhost:5432, Redis: localhost:6379

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

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/upload` | Upload `.pcap` → create analysis job |
| GET  | `/api/v1/jobs` | List jobs |
| GET  | `/api/v1/jobs/{id}` | Job status/progress |
| GET  | `/api/v1/jobs/{id}/sessions` | Per-session results |
| GET  | `/api/v1/jobs/{id}/findings` | Findings (severity-sorted) |
| GET  | `/api/v1/jobs/{id}/shap` | SHAP explanations |
| GET  | `/api/v1/jobs/{id}/fleet` | Fleet summary metrics |
| GET  | `/api/v1/jobs/{id}/report.{json\|html\|pdf}` | Report export |
| GET  | `/api/v1/health`, `/metrics` | Health + Prometheus metrics |

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
