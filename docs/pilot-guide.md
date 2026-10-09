# Pilot guide (for mail/infra admins and security consultants)

## Prerequisites

- A Linux host (or K8s cluster) with a SPAN/mirror port or TAP feeding mail
  VLANs, OR a directory of archived PCAPs for a dry run.
- Postgres 16 + Redis 7 (managed preferred; compose provides both for eval).
- 4 vCPU / 8 GB RAM minimum for evaluation; see `docs/sizing.md` (measured
  numbers only — size from your own replay test, not our table).
- Outbound HTTPS for MTA-STS policy fetches (optional; DNS failures degrade
  to `dns-error`, never to false verdicts).

## 1-hour install path (evaluation)

```bash
git clone <repo> && cd CipherPost
cp .env.example .env   # fill POSTGRES_PASSWORD, JWT_SECRET (openssl rand -hex 32), ADMIN_PASSWORD
docker compose -f docker/docker-compose.yml up --build
# or: helm upgrade --install cipherpost ./deploy/helm/cipherpost --namespace cipherpost --create-namespace
```

Then: log in as bootstrap admin → create per-operator accounts → rotate the
bootstrap password → configure one alert channel → replay a fixture
(`--profile replay`) or upload a PCAP → open `/app/live`.

## What to measure in the first two weeks

1. **Coverage**: `GET /api/v1/agents` shows every sensor `online`; session
   counts match mail volume expectations.
2. **Noise**: findings/day per rule; suppress legacy systems you cannot fix
   (`Suppress` action) instead of disabling alerts.
3. **Accuracy**: label a sample via finding feedback (confirmed/false
   positive); watch `/api/v1/feedback/precision` per rule.
4. **Operations**: any `dead-letter` depth, capture drops, or `degraded`
   health — attach a diagnostics bundle (`/api/v1/diagnostics/bundle`).

## How to report problems

Open an issue with the bug template + diagnostics bundle (opt-in, redacted).
For vulnerabilities: `SECURITY.md` private process only.

## Known limitations (read before judging output)

- 27-rule 100% precision/recall is synthetic-corpus only (lab set: 28
  captures, 94 sessions, `docs/evidence/real-eval.md`); real-world
  precision is unknown — your feedback labels are the evaluation.
- MTA-STS/DANE needs `CIPHERPOST_DNS_RESOLVER` + trust anchor; otherwise
  `not-published`/`dnssec-failed`, never guessed.
  Last verified: unit/fake-DNS tests only; no live resolver run recorded —
  see `docs/evidence/` for what has actually run.
- ML scores are rules-derived prioritization, not ground truth.
- Single sensor sees one segment; 30-day live run minimum before trusting trends.

## Data handling summary (for your security review)

Full detail in `docs/security-review-pack.md`. In short: raw packets stay on
the sensor host (rolling 6 h window, never backed up); the server stores
session metadata + findings + cert facts; agents ship metadata only (no mail
content, tested); retention purges on schedule unless legally held.
