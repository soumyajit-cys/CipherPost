# Item 3 evidence: first real labeled capture set (lab-generated)

Date: 2026-10-05. 28 captures (23 mail + 5 PQ from Item 2), 94 sessions.
`eval_real.py`: **0 misses, 0 false positives** on all labeled rules.

## Plain statement of limits

This set is **lab-generated and small**. It supports functional-correctness
claims only (the tool reads real wire bytes and reports what its rules say),
NOT claims about performance on arbitrary production traffic. No external
pilots, no customer data, no third-party servers contacted. RC4/3DES could
not be tested (removed from OpenSSL 3.6: `openssl ciphers -v 'RC4-SHA'` and
`'DES-CBC3-SHA'` both return "no cipher match"); weakest available
`TLS_RSA_WITH_AES_128_CBC_SHA` used instead.

## How it was built (all on 127.0.0.1, this host)

- Servers: `scripts/lab_mail.py` (stdlib sockets+ssl, real handshakes);
  STRIPTLS proxy: `scripts/lab_strip_proxy.py`; driver: `scripts/lab_capture.sh`.
- Clients: `openssl s_client` 3.6.1 (`-starttls smtp/imap/pop3` or direct)
  and a stdlib implicit-TLS client (`client-implicit` mode, RST-close).
- Capture: `dumpcap -i lo`, filtered per scenario port, classic pcap.
- Certs: lab CA + good/expired(0-day)/self-signed/wrong-host/sha1 certs
  (openssl, 2026-10-05; details in manifest `source` fields).
- Dialogs paced ~1s/line: sub-second full dialogs intermittently vanish
  from loopback capture on this host (host-specific AF_PACKET quirk under
  background QUIC bulk load); pacing changes timing only, never bytes.
- Toolchain: OpenSSL 3.6.1, tshark/dumpcap 4.6.4, Python 3.13 + stdlib ssl.

## Scenario table (config → expected → observed)

TLS session is the last session in each file (probes/polls precede it),
except `smtp_stripped_proxy587` (single session).

| Capture | Config | Expected (from config) | Observed |
|---|---|---|---|
| mail_smtp13_starttls587 | STARTTLS→1.3, good cert | clean | clean |
| mail_smtp12_starttls587 | STARTTLS→1.2, good cert | untrusted (lab CA) | untrusted |
| mail_smtp10_starttls587 | pinned 1.0, AES128-SHA | tls1-0, outdated, weak/non-aead/non-pfs/no-pfs-suites, untrusted | all 7 |
| mail_smtp11_starttls587 | pinned 1.1, AES128-SHA | tls1-1 + same weak set + untrusted | all 7 |
| mail_smtp_weakcbc587 | 1.2, AES128-SHA forced | weak/non-aead/non-pfs/no-pfs-suites, untrusted | all 5 |
| mail_smtp_expired587 | 1.2, 0-day cert | expired, untrusted | both |
| mail_smtp_self587 | 1.2, self-signed | self-signed, untrusted | both |
| mail_smtp_wronghost587 | 1.2, CN=other.host.test | untrusted; hostname-mismatch NOT expected (see below) | untrusted only |
| mail_smtp_weaksig587 | 1.2, sha1 cert + AES128-SHA | weak-signature + weak set + untrusted | all |
| mail_smtp13_expired_blind587 | 1.3, expired cert | NOTHING (TLS 1.3 certs unobservable) | clean |
| mail_smtp_nostarttls587 | no STARTTLS offered | plaintext, no strip | both as expected |
| mail_smtp_strip_ignored587 | offer ignored, AUTH clear | plaintext + strip-attempt | both |
| mail_smtp_stripped_proxy587 | proxy strips offer | plaintext; NO strip-attempt (offer invisible = honest limitation) | exactly that |
| mail_smtp12_implicit465 | implicit 1.2 | untrusted; no no-tls-on-implicit | as expected |
| mail_smtp13_implicit465 | implicit 1.3 | clean | clean |
| mail_smtp10_implicit465 | implicit 1.0 | tls1-0 + weak set + untrusted | all 7 |
| mail_imap13_starttls143 | STARTTLS→1.3 | clean | clean |
| mail_imap_plain143 | no STARTTLS cap | plaintext | plaintext |
| mail_imap13_implicit993 | implicit 1.3 | clean | clean |
| mail_pop13_stls110 | STLS→1.3 | clean | clean |
| mail_pop_plain110 | no STLS cap | plaintext | plaintext |
| mail_pop12_implicit995 | implicit 1.2 | untrusted | untrusted |
| mail_imap12_login143 | STARTTLS→1.2 + LOGIN | untrusted (LOGIN inside TLS: no cred finding by design) | untrusted |
| pq_* (5, Item 2) | hybrid/classic/gap/HRR/abort | Section "PQ" of pq-interop.md | agree, 0 FP/FN |

`eval_real.py` output (2026-10-05): per-rule precision/recall 1.00 everywhere
labels exist (12 untrusted TP, 5 weak-cipher TP, 5 plaintext TP, ...);
zero misses, zero false positives. Full output archived in CI logs; command:
`PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json`.

## diff_tshark.py: reported disagreements are a script artifact

The script reads tshark JSON field `tls.handshake.ciphersuite`, which is
empty for TLS 1.3 ServerHello (and some 1.2). Direct queries agree
everywhere checked:
- mail_smtp10 (ours `TLS_RSA_WITH_AES_128_CBC_SHA`) vs tshark `0x002f` ✓
- mail_smtp12 (ours `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`) vs tshark `0xc030` ✓
- (Item 2: hybrid `0x11ec`=4588, classic `0x001d`=29 ✓)
Script improvement left as follow-up (known-issues entry).

## Bugs found and fixed (with tests, re-run shown)

1. **Zero-byte sessions flagged HIGH** (`plaintext-mail-protocol` on
   SYN/RST-only refused probes and banner-only polls, alleging credential
   exposure with zero bytes observed). Fix: require `plaintext_bytes > 0`
   in `rule_ssl_in_plaintext` and `rule_no_tls_on_tls_port`
   (`backend/app/parsing/rules.py`). Test:
   `test_zero_byte_sessions_get_no_cleartext_findings` (fails before,
   passes after). Full suite 207 passed; synthetic corpus eval still
   45 findings, 0 FP/FN. Junk sessions in this corpus are now finding-free.
2. **ServerHello key_share with key_exchange missed** (Item 2, same run).

## NOT fixed / known limits (honest)

- `hostname-mismatch` live path (publicly-trusted chain + wrong name) has
  no lab coverage: our wrong-host cert fails the chain first by design
  (`validate_chain` returns chain errors before hostname check). Labeled
  `present:false` with rationale. Needs a publicly-trusted wrong-name cert
  (owner action) — recorded in known-issues.
- RC4/3DES-specific rules (`rc4-cipher`, `3des-cipher`, export) have no live
  coverage (ciphers absent from OpenSSL 3.6).
- Incomplete-stream sessions (no FIN/RST before capture end) are dropped
  silently by reassembly `emit()` — by design pending pilot demand; lab
  harnesses close deterministically (server RST + client kill) so every
  committed capture parses fully. Noted in what-we-cannot-see.md.
- Labels by session index are stable only because pcaps are frozen
  artifacts; `eval_real.py` re-verifies on every run.
