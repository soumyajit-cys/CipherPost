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
```

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
