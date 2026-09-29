# CipherPost Threat Model

## 1. What this tool protects against

CipherPost is a **passive network observer** for email transport security. It
detects, in live traffic or archived captures:

- **Downgrade attacks** — STARTTLS stripping (`starttls-strip-attempt`),
  missing TLS on implicit-TLS ports, unauthenticated plaintext sessions.
- **Weak transport cryptography** — SSLv3/TLS 1.0/1.1, export/RC4/3DES/
  non-AEAD ciphers, non-PFS key exchange, short keys, weak signatures.
- **Certificate failures** — expired, not-yet-valid, self-signed, untrusted
  chains — plus **forecast** expiry before it breaks (`/api/v1/certs/expiring`).
- **Fleet drift** — sudden posture changes and feature-distribution shifts
  that indicate policy regressions or new infrastructure.

It does **not prevent** attacks — it has no inline blocking capability. Its
value is detection speed (seconds on the wire) plus forensic evidence.

## 2. What it explicitly does NOT protect against

- Endpoint compromise, credential theft, mailbox intrusion.
- Message-content threats (phishing, malware attachments, BEC).
- Active MITM *prevention* — CipherPost observes; enforcement belongs in
  MTA-STS/DANE deployment (see `app/proactive/mta_sts.py`, currently a
  capability stub, and Track 2 notes).
- DNS-layer attacks (until MTA-STS/DANE checking is enabled with a resolver).
- Attacks below TCP (L2 games) or outside mail ports (BPF-filtered out).

## 3. CipherPost's own attack surface

The sensor parses **untrusted bytes from potentially hostile networks**.
Treat every packet, handshake field, and certificate as attacker-controlled.

| Surface | Threat | Mitigation in repo |
|---|---|---|
| Link/IP/TCP parsing (dpkt, scapy) | malformed frames → crash / OOM | `packets.py` normalizers return `None` on any exception; feed path wrapped in try/except; fuzz tests |
| TLS record/handshake parsing | crafted ClientHello/ServerHello → over-read, exception, state confusion | bounds-checked manual parser (`tls_records.py`, `handshake.py`); per-record try/except; `test_stage6_robustness.py` + live-packet fuzz |
| X.509 parsing (cryptography, pyOpenSSL) | malicious certs (oversized extensions, bad dates) | `analyze_certificate` traps parse failures into findings, never crashes |
| STARTTLS plaintext | injection / banner spoofing | plaintext treated as data only; transition requires real TLS bytes after the offer |
| PCAP upload | malicious/zip-bomb captures | 500 MB cap, `.pcap` gate, per-packet exception isolation |
| Redis streams / Postgres | injection via crafted fields | ORM + parameterized queries everywhere; no string-built SQL except static DDL |
| Alert webhooks / syslog / tickets | SSRF-ish exfil via alert content | adapters POST fixed schemas to operator-configured URLs only |
| Dashboard/API | unauthenticated access, session hijack, token leak in URLs/logs | PyJWT HS256 pinned (exp required, alg=none rejected) + API keys, RBAC, audit log incl. `auth.login.failed` (`docs/auth.md`); login lockout (5/5min acct, 20/5min IP, generic 401); CORS allowlist `CIPHERPOST_CORS_ORIGINS` (default same-origin); SSE via `POST /api/v1/live/ticket` (60s single-use `live:read`) — main tokens in URLs rejected; use TLS in front |
| Secrets | committed credentials, weak defaults | `CIPHERPOST_ENV=production` (default) refuses weak `JWT_SECRET` (<32B/default) and admin password (<12ch/default) at startup; `dev` uses ephemeral secret + warning; `.env` untracked (rotated guidance in DEPLOYMENT.md); `.env.example`, DB password via env/secret only, pre-commit gitleaks, CI secret scan |
| Supply chain | vulnerable deps/images | Pinned `backend/requirements.txt` from `requirements.in` (+ `greenlet`, `PyJWT`, `alembic`), Dependabot (pip/npm/docker/actions), CI `pip-audit`, `npm audit`, Trivy image scan |

## 4. Robustness test mapping

- `test_stage6_robustness.py` — malformed PCAPs, truncated records, garbage
  handshakes, adversarial certs → no crash, bounded findings.
- `test_stage7_live.py` — live-packet path fuzz (`test_fuzz_live_packets_no_crash`),
  replay determinism (live == batch), retention purge, dedup logic.
- `test_track3_agents.py` — stream consumer-group exactly-once semantics.
- CI (`.github/workflows/ci.yml`) runs all of the above plus synthetic-corpus
  rules-eval and ML-eval gates (explicitly labelled synthetic, not real-world)
  plus `scripts/eval_real.py` (empty manifest, informational) and
  `migrate-check` (empty Postgres → head + `alembic check` no-drift) on every PR.
- Phase 1 additions: `test_phase1_config.py` (startup refusal), `test_phase1_auth.py`
  (PyJWT alg-none/expiry/tamper, SSE single-use, lockout, CORS),
  `test_phase1_migrate.py` (raw tables in metadata/migration), `test_phase1_eval.py`
  (real-harness miss/false-positive reporting, tshark diff runner).

## 5. Residual risks (accepted, documented)

1. **Evasion by fragmentation** — extreme handshake fragmentation across many
   records may parse as `tls-handshake-incomplete` (medium) rather than the
   precise underlying issue. Reassembly caps bound the cost of trying harder.
2. **Encrypted visibility limit** — post-handshake TLS content is opaque; a
   session that negotiates strong crypto and then misbehaves at the SMTP
   layer is out of scope by design.
3. **Single-sensor blind spots** — one SPAN port sees one segment; deploy
   multiple capture agents (DaemonSet) for coverage; watch `/api/v1/agents`.
4. **ML label circularity** — initial labels derive from the rules engine
   (documented in README + disagreement reports); treat scores as
   prioritization, never as ground truth. Synthetic 100% P/R does not imply
   real-world performance — see `tests/real/` (empty, human-labelled harness
   + tshark diff, not a gate).
5. **Deployment hardening verified by code review, not by running containers**
   (Docker/K8s non-root, unexposed DB/Redis, migrate gating were not
   executed here — verify with `docker compose config` + staging deploy).
   Time handling is now tz-aware, but stored DB timestamps may mix naive
   legacy rows with aware new rows — comparisons normalize to UTC.
