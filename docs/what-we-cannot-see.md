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
