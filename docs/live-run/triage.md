# Triage: bug vs noise vs expected behavior vs documented limitation

How to classify anything the live run surfaces, and how to confirm a false
positive or a miss before filing it. Companion pieces:
`docs/live-run/daily-log-template.md` (what to record daily) and the GitHub
issue templates (`.github/ISSUE_TEMPLATE/`).

## The four categories

| Category | Meaning | Typical disposition |
|---|---|---|
| **Bug** | The tool's own behavior contradicts its documented contract (parser crash, wrong rule firing on valid data, counts that do not match the DB). | Fix in code + regression test; never "tune away" silently. |
| **Noise** | The rule worked as documented, but fires on traffic the operator cannot act on (a legacy appliance you already know about). | Suppression with scope + expiry (`docs/` suppressions flow), or accepted-risk feedback label — never a code change. |
| **Expected behavior** | The tool did exactly what the docs say, even if the result is unwelcome (e.g. `plaintext-mail-protocol` on a deliberately plaintext path). | No change; record as understood. If the *severity* feels wrong, file evidence — severities change only with label data, not intuition. |
| **Documented limitation** | The tool cannot see the evidence at this capture point (TLS 1.3 certificate rules skip, downstream-of-strip blindness, JA4S layout experimental). `docs/what-we-cannot-see.md` is the list. | No bug; label feedback if a finding was wrongly expected; possibly a probe-visibility improvement request (opt-in, authorized hosts only). |

The decision path: **is the observed output consistent with
`docs/what-we-cannot-see.md` + the rule's documented trigger?** If yes →
expected behavior or documented limitation. If the output contradicts the
docs → bug. If the output matches the docs but is operationally useless →
noise.

## Confirming a false positive (before labeling it)

1. **Reproduce from the stored session**: export the bundle
   (`scripts/export_issue_bundle.py --session <id>`), re-run the engine on
   the session's stored evidence where available, and check the rule's
   evidence fields against the rule's documented trigger.
2. **Compare with the original capture** while the raw window still exists
   (`RAW_RETENTION_SECONDS`, default 6 h): open the PCAP slice in tshark and
   verify the on-the-wire facts the rule claims (e.g. really did the server
   select TLS 1.0? does the certificate really chain to your trust store?).
3. **Check the real configuration** on the mail server: the config that was
   live at the time (`postconf smtpd_tls_*`, `doveconf ssl_*`) — not the
   config you believe is live.
4. Only then label `false_positive` via the feedback endpoint with a comment
   saying what steps 1–3 showed. Pass `triage_category` in the same call
   (`bug | noise | expected-behavior | documented-limitation` — the API
   validates it and stores it as a machine-readable comment prefix that
   `scripts/export_labels.py` exports with the rest of the provenance).
   The label exports with provenance
   (`scripts/export_labels.py`) and feeds precision dashboards — an
   unconfirmed label poisons that dataset.

## Confirming a miss (before filing one)

A miss is only a miss if **the capture point could have seen the evidence**:

1. Identify what evidence would have been on the wire at your capture point
   (e.g. ServerHello selecting a weak version; a certificate in a ≤1.2
   handshake).
2. Check visibility limits first (`docs/what-we-cannot-see.md`): TLS 1.3
   certificate content, downstream-of-strip offers, and unobserved ports are
   documented limitations, not misses.
3. Confirm the capture point was actually positioned to see it
   (`docs/live-run/capture-placement.md` checklist) and was up during the
   window (no zero-session gap in the live report).
4. If all four hold and no finding was raised: file `missed_detection` with
   the bundle and the tshark excerpt proving the evidence was on the wire.

## Severity scale and response targets

| Severity | Meaning | Response target (from the owner during the run) |
|---|---|---|
| **S1** | Capture blind / pipeline down / data loss — the run itself is invalid while it lasts. | same day; note window of blindness in the daily log and treat that window as excluded from exit-criteria coverage. |
| **S2** | Pipeline degraded but running (DLQ growth, alert channel down, disk guard tripped) — results partial. | within 24 h; document mitigation. |
| **S3** | Wrong or noisy output (false positives, misses) — measurements tainted but pipeline healthy. | within the week; bundle + label, no rush fix. |
| **S4** | Cosmetic / documentation / wishlist. | next batch review; no run impact. |

These targets are the owner's operating commitment during the 30-day run,
not a product SLA — nothing here implies a supported product.
