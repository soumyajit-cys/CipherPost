# CipherPost — Live/Always-On Design Notes

This document captures the short design note written before each build stage of
the always-on live acquisition mode (NTRO PS 26159). It complements the README.

---

## Stage 1 — Test environment & traffic generation

**Goal.** A deterministic source of *live* email-protocol traffic (SMTP/IMAP/POP3)
across the same scenario matrix the offline corpus covers, so the capture daemon
can be observed and tested without a human uploading files.

**Decisions.**
- **Two complementary generators.**
  1. A **Python traffic generator** (`scripts/traffic_generator.py`) that runs
     per-scenario in-process TLS mail listeners locally and drives real client
     connections against them (on `lo` by default). It covers the adversarial
     matrix — expired / self-signed / untrusted-chain certs, TLS 1.2/1.3, and
     STARTTLS-stripping servers — deterministically, in a loop, with jitter.
     It is also a **probe**: modern OpenSSL refuses RC4/EXPORT/TLS-1.0; those
     scenarios are skipped with a warning at runtime rather than failing.
  2. A **Docker mail lab** (`docker/mail-lab/`) running real Postfix + Dovecot
     to validate the "actual email infrastructure" claim; the traffic generator
     can drive it via `MAIL_LAB_*` env (STARTTLS chaining to Postfix).
- **Static PCAP ground truth already exists** in `tests/fixtures/` (16 labeled
  scenarios + `corpus_index.json`). These feed the deterministic replay harness
  (Stage 6) — the lab/generator are for live demos and manual testing.
- Generators must be latchable to quiet periods (they produce traffic in bursts
  with jitter, not a constant screech) so alert-storm / rate-limit behavior can
  be exercised honestly.

---

## Stage 2 — Live capture daemon & streaming session reconstruction

**Goal.** Always-on capture worker: attach to a SPAN/TAP-fed interface in
promiscuous mode, filter to email ports, reconstruct sessions *incrementally*
as packets arrive, emit completed `Session` objects onto a Redis stream.

**Decisions.**
- **One packet-agnostic ingestion point.** A normalized `Packet` (timestamp,
  5-tuple, seq/ack, TCP flags, payload, raw frame) is produced by either a
  scapy live sniffer or a pcap iterator (replay). Both feed the *same*
  streaming reassembler — so "analysis doesn't care where packets came from".
- **Incremental reassembly via existing engine.** The Stage-2 `StreamAssembler`
  is already online (feed-per-packet). We subclass it into a `LiveReassembler`
  that adds: idle-timeout finalization, per-stream byte caps, max concurrent
  sessions with oldest-server eviction, and *incremental* draining of finished
  sessions (FN/RST or idle). Sessions that close by cap are flagged.
- **Bounded memory.** Hard caps (`max_sessions`, `max_buffer_bytes` per stream)
  checked on every feed; evictions/drops are counted and logged, never fatal.
- **Rolling raw capture retention.** A `RollingRawStore` appends every original
  frame into time-chunked segment files and purges segments older than a
  configurable window (default 6h). Each emitted `Session` carries
  `raw_refs` = list of (segment, offset, length) so its exact frames can be
  replayed for forensics *while within the retention window*; older references
  resolve to "purged".
- **Emission.** Completed sessions → Redis Stream (`cipherpost:sessions`);
  `capture:stats` Pub/Sub heartbeat for the dashboard + /metrics.

---

## Stage 3 — Consume sessions, TLS/cert analysis, validate

**Goal.** Analysis worker drains `cipherpost:sessions`, applies the *existing*
Stage-3 engine (handshake parse, X.509 chain validation, deterministic rules)
to each `Session`, and emits analyses/findings. Validate precision/recall
against Stage-1 ground truth through the replay harness.

**Decisions.**
- **Reuse, don't fork.** `analyze_session(session)` from `app.parsing.analysis`
  is the single entry point — file and live paths share one auditable engine.
- Serialization: `Session` objects are serialized to Redis Stream entries
  (JSON) including reassembled byte segments (starttls/plaintext/tls) so the
  analysis worker is stateless; blob segments are short-lived by design.
- **Validation gate.** `eval_rules` against the labeled corpus must stay
  green (currently 43/43 → 100% P/R) before Stage 4.

---

## Stage 4 — ML risk scoring, rolling fleet baseline, SHAP

**Goal.** Every analyzed session gets a 0–100 posture score, an Isolation
Forest anomaly decision against the *current* fleet, and SHAP explanation.

**Decisions.**
- **Fleet baseline is a rolling window, not a static fit.** A `RollingBaseline`
  stores per-session feature vectors (+ ts) in Postgres and refits the
  Isolation Forest over the trailing window (default 7 days, min-sample
  guards). It updates lazily (on crossing refit interval or day boundary).
- Known limitation (unchanged): labels derive from the rules engine; surfaced
  via SHAP + rule-vs-ML disagreement (35 in `ScoringResult`).
- Findings + scores → Redis Stream `cipherpost:findings` + Pub/Sub fan-out for
  SSE; persisted to Postgres.

---

## Stage 5 — Alerting, storage, reporting, live dashboard

**Goal.** Real-time alerting (pluggable adapters), historical query, and a
live SSE-updating dashboard.

**Decisions.**
- **Alert dispatcher** consumes `cipherpost:findings`; threshold
  (`alert_min_severity`), per-rule dedup window, and global rate-limit prevent
  alert storms; adapters: **webhook** (base), **slack**, **syslog/CEF**, and a
  pluggable base class. Configurable per channel (API + env).
- **SSE (not polling).** FastAPI streams `cipherpost:live:*` Pub/Sub channels
  to the browser via `text/event-stream`. A `Last-Event-ID`-style replay badge
  touches the stored streams for missed events.
- Reporting: existing per-job reports retained; a new time-window fleet trend
  endpoint (`/api/v1/fleet/trend`) serves the posture-over-time chart from the
  live store.

---

## Stage 6 — Replay harness, hardening, deployment

**Goal.** Deterministic regression for the live path, fuzz/load hardening,
full dockerized deployment with host-networking docs.

**Decisions.**
- **Replay harness** (`scripts/replay_harness.py`): feeds recorded PCAPs
  through the *live* capture path (scapy live-speed over an interface, or
  direct pcap iteration into capture worker replay mode). This is the test &
  demo mode; `pytest` uses the direct feed path (no network needed).
- **Fuzz + load**: parsers treat all bytes as untrusted (existing
  `test_stage6_robustness` extended to the live packet path); load test drives
  high packet volume and asserts graceful drop/sampling with counters, no
  unbounded memory.
- **Deployment**: `capture` (host network, `CAP_NET_RAW`/`CAP_NET_ADMIN`),
  `analysis` worker, `alerts`, `api`, `frontend`, `db`, `redis`, `mail-lab`,
  `traffic-gen`. Structured JSON logs + Prometheus `/metrics` (packets/sec,
  sessions tracked/dropped, queue depth, alert latency).