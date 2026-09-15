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
| Dashboard/API | unauthenticated access, session hijack | JWT + API keys, RBAC, audit log (`docs/auth.md`); SSE accepts `?token=` — tokens are bearer secrets, use TLS in front |
| Secrets | committed credentials | `.env` untracked (was committed historically — rotated guidance in DEPLOYMENT.md); `.env.example`, pre-commit gitleaks, CI secret scan |
| Supply chain | vulnerable deps/images | CI `pip-audit`, `npm audit`, Trivy image scan |

## 4. Robustness test mapping

- `test_stage6_robustness.py` — malformed PCAPs, truncated records, garbage
  handshakes, adversarial certs → no crash, bounded findings.
- `test_stage7_live.py` — live-packet path fuzz (`test_fuzz_live_packets_no_crash`),
  replay determinism (live == batch), retention purge, dedup logic.
- `test_track3_agents.py` — stream consumer-group exactly-once semantics.
- CI (`.github/workflows/ci.yml`) runs all of the above plus rules-eval and
  ML-eval gates on every PR.

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
   prioritization, never as ground truth.
