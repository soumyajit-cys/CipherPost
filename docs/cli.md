# `cipherpost` CLI (fully offline)

No server, database, or Redis required. The CLI uses the same `app.parsing`
engine as the server and the sensor agent.

```bash
pip install cipherpost            # not published yet; from source: pip install -e .
cipherpost scan capture.pcap --format json --fail-on high
cipherpost scan capture.pcap --format sarif > results.sarif
cipherpost verify-domain example.com
cipherpost rules list
cipherpost rules explain expired-certificate
cipherpost version
cipherpost evidence capture.pcap > evidence.json
```

## Evidence bundles (audits)

`cipherpost evidence capture.pcap` emits a hash-chained bundle
(`manifest` + `records`): every record links to the previous SHA-256 so
tampering is detected on verify. The manifest records `record_count`,
`root_hash`, tool/rules/mapping versions, and observed vs unobservable
label tallies. The server exposes the same bundle per completed job at
`GET /api/v1/jobs/{id}/evidence`. Unobservable items are labeled, never
filled in.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | clean — no unsuppressed findings at/above `--fail-on` (default `high`) |
| 1 | findings at/above the threshold (including `verify-domain` problems) |
| 2 | usage/error — bad flags, missing file, bad baseline/suppressions file |
| 3 | parse failure — unreadable or corrupt PCAP |

## Filtering accepted findings

- `--baseline accepted.json`: `{"ignore": [{"rule_id": "...", "five_tuple": "...?"}]}`
  (omit `five_tuple` to ignore a rule everywhere).
- `--suppressions sup.json`: `{"suppressions": [{"rule_id": "...", "scope": {...}}]}`
  using the server's scope format (`hosts`, `cidrs`, `domains`, `ports`).
  Suppressed findings are still shown, marked `"suppressed": true`.

## JSON schema (versioned)

Top level: `{schema_version: 1, cipherpost_version, pcap, sessions[]}`.
Each session: `{session_id, protocol, five_tuple, tls_version, cipher,
findings[]}`; each finding:
`{rule_id, rule_name, severity, title, description, reference[, suppressed,
suppression_id]}`. SARIF follows schema 2.1.0 for GitHub code scanning.

## Offline guarantee

`scan` and `rules` never touch the network. `verify-domain` performs live
DNS/HTTPS only for the named domain and reports `dns-error` honestly when
offline. The CLI never imports fastapi/redis/sqlalchemy/celery (tested).

## Opt-in active probe (authorized hosts only)

```bash
cipherpost probe mail.example.com:25
cipherpost probe mail.example.com:993 --no-starttls
```

Prints the presented chain as JSON for joining to passive TLS 1.3 data by
host. Consent notice prints on every run: only probe hosts you own or have
written permission to test. Safeguards: 10 s timeouts, one probe per host per
60 s, private/loopback ranges blocked unless `--allow-private` (lab only),
no server-side probe API exists by design. See `docs/what-we-cannot-see.md`.
