# Real captures (human-labelled) — contribution guide

The 100% precision/recall in CI is measured on a **synthetic corpus** produced by
`scripts/traffic_generator.py` (`tests/fixtures/`). That is circular by design:
it proves the parser + rules match the generator, not that they match the real
world. This directory is the foundation for measuring against real traffic
**without inventing data**: it starts empty (manifest with zero entries).

## Manifest format (`manifest.json`)

```json
{
  "version": 1,
  "captures": [
    {
      "pcap": "smtp_starttls_real_01.pcap",
      "source": "lab postfix 3.7, TLS 1.2, StartTLS on port 587",
      "license": "CC0 - captured by <you> on <date>, sanitized",
      "capture_notes": "client: openssl s_client; server: local postfix",
      "expected_findings": [
        {"rule_id": "deprecated-tls-version", "session": "0", "present": false},
        {"rule_id": "expired-certificate", "session": "0", "present": true, "notes": "leaf expired 2024-01-01"}
      ],
      "notes": "human label rationale, links to analyst review"
    }
  ]
}
```

Fields:

- `pcap`: path relative to `tests/real/` (commit the `.pcap` alongside the manifest).
- `source`: where/when/how it was captured (host, MTA, TLS setup).
- `license`: redistribution license — **only commit captures you may share**
  (CC0, internal-approved, or public datasets). Never commit customer traffic.
- `expected_findings`: human labels per `rule_id` per session index (`session`
  is the analyzer's session order for that PCAP, or five-tuple if stable).
  `present: true/false` + `notes` with evidence (e.g. `openssl x509 -text`).
- `notes`: labelling rationale, reviewer, date.

## How to contribute a capture

1. Capture with `tcpdump -i <iface> -w capture.pcap 'tcp port 25 or 587 or ...'`
   (or export from your sensor). Sanitize payloads if needed (rules only need
   handshakes + certs; truncate application data after handshake if policy requires).
2. Run `scripts/diff_tshark.py tests/real/<your>.pcap` to cross-check our TLS
   version/cipher/cert subjects against tshark. Attach disagreements to your review.
3. Label expected findings by hand (read the PCAP in Wireshark/tshark + check certs
   with `openssl`). Get a second analyst to review labels.
4. Add the entry to `tests/real/manifest.json` and run:
   `PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json`
5. Open a PR with the PCAP + manifest entry + eval output. Real-data eval is
   informational (not a CI gate) until the corpus is large and stable.

## What is NOT here

- No fabricated PCAPs or labels. Empty manifest = honest baseline.
- Synthetic-corpus eval stays in CI but is labelled "synthetic corpus"
  (see `scripts/eval_real.py --synthetic` note and CI step names).
