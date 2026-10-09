# What CipherPost cannot see (visibility limits)

Passive observation has hard limits. Where the tool cannot see something it
reports `not observable` — it never guesses, and never raises a finding on
data that was not observed. Per-session detail lives in
`visibility: {tls13, cert_chain, sni, hrr, offered_groups, selected_group}`;
rules that needed missing data list their ids in `not_observable`.

## TLS 1.3 encryption boundaries

- **Certificate contents**: encrypted in TLS 1.3. `cert_chain` is
  `not_observable_tls13` unless real X.509 certs parsed from observed bytes
  (synthetic/test captures may carry plaintext). The six certificate rules
  (expired, not-yet-valid, self-signed, untrusted chain, weak signature,
  short key) skip these sessions instead of passing or failing.
- **What IS observable in 1.3**: ClientHello (versions, ciphers, groups,
  key-share offers, signatures, ALPN, SNI, ECH outer, PSK modes), ServerHello
  (selected version/cipher/group, HRR, downgrade sentinels), handshake
  timing, and plaintext before STARTTLS.
- Closing the gap (opt-in, authorized hosts only): `cipherpost probe
  host:port` records the presented chain out-of-band for joining by host.
  There is deliberately no server-side probe API. Probing hosts you are not
  authorized to test may be unlawful — see the consent notice on every run.

## Encrypted Client Hello (ECH)

- An ECH outer (ext `0xfe0d`) means the inner SNI and parameters are
  encrypted: `sni` is reported as `ech_outer`, never the outer name as the
  real destination. Certificate/host attribution for such sessions is limited
  to the outer (public) name. Presence is reported as INFO, nothing more.

## Downgrade evidence vs posture notes

- A server-random downgrade sentinel (RFC 8446 §4.1.3) is a CRITICAL finding
  **only** when the client demonstrably offered higher (proven). A 1.3 offer
  negotiating 1.2 is an INFO posture note (the server may simply lack 1.3).
- HelloRetryRequest is normal TLS 1.3 operation; only a selected group the
  client never offered is flagged.

## STARTTLS stripping: what a downstream sensor can and cannot say

- A passive capture point sees only the bytes that reach it. If an on-path
  attacker strips the STARTTLS offer upstream, the offer never appears in the
  capture: the tool reports absence of TLS (`plaintext-mail-protocol`) plus
  any plaintext-continuation evidence — it cannot reconstruct the unseen
  offer and never alleges a specific stripping event it did not observe.
- `starttls-strip-attempt` fires only when the offer IS on the wire
  (server advertised, or client requested) and no TLS handshake follows.
  A stripped offer is therefore reported as plaintext, not as stripping;
  the proxy case in `tests/real/` (`smtp_stripped_proxy587`) pins this
  behavior: plaintext true, strip-attempt false.

## GREASE

GREASE values (RFC 8701) appear throughout hellos and are stripped before
any analysis or fingerprinting. They are counted, never findings.

## Fingerprints (JA3/JA4)

Fingerprints describe the *offered* stack, not identity: NAT, shared
libraries, and middleboxes collide routinely. Treat matches as triage hints;
the allow/deny list is yours to manage. Vectors in tests are self-derived
unless stated otherwise.

## ML scores

Scores rank sessions for review; SHAP bars show what drove a score, never
evidence of a vulnerability. See `docs/ml-evaluation.md`.

## Fingerprint spec basis (JA4/JA4S)

Client JA4 reproduces the official worked example
(`t13d1516h2_8daaf6152771_e5627efa2ab1`); JA4S layout follows the reference
implementation's `to_ja4s` behavior (GREASE included in count+hash).
Hybrid post-quantum group detection verified against OpenSSL 3.6.1
loopback captures with tshark 4.6.4 decode (X25519MLKEM768 negotiated,
selected, and gap cases).

Last verified: 2026-10-05, FoxIO JA4 spec + reference code (read-only),
OpenSSL 3.6.1, tshark 4.6.4 — evidence `docs/evidence/ja4-verification.md`,
`docs/evidence/pq-interop.md`.
