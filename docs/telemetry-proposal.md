# Usage telemetry proposal (DESIGN ONLY — not implemented, nothing is sent)

Status: proposal for owner approval. No telemetry code exists in this repo;
no data leaves any deployment. If approved, implement behind a separate
explicit opt-in (`CIPHERPOST_TELEMETRY_OPT_IN=true`, default off) with the
guarantees below, or reject this proposal entirely.

## Purpose (why consider it at all)

Rule precision in the wild is currently unknown (synthetic corpus only).
Aggregate, anonymous counts of finding volumes per rule would let maintainers
prioritize parser work without seeing anyone's mail infrastructure.

## What would be collected (and only this)

- CipherPost version, install kind (compose/helm/agent count bucket).
- Per-rule finding COUNTS per day (integers only).
- Error counters (parse failures by category).

Explicitly never: five-tuples, IPs, hostnames, certificates, payloads,
email content, org names, usernames, raw sessions.

## Privacy design

- Aggregation on-device; only daily counters transmitted.
- No unique instance IDs (random per-boot reporter id, never persisted).
- Publish the exact payload schema in-repo; third-party audit before enablement.
- Kill switch: setting the env var to false stops everything; documented
  firewall rule (blocklist the endpoint) as a second stop.
- Data retention on receipt: 90 days, then aggregate-only.

## Open questions for the owner

1. Is even this minimal collection worth the trust cost with pilot orgs?
2. Self-hosted collector vs vendor endpoint?
3. Default-off forever, or default-on with first-run notice? (Recommendation:
   default-off forever for a security tool.)
