# Task 6 evidence: edge-session audit (2026-10-10)

Command: `PYTHONPATH=backend python -m pytest backend/tests/test_edge_sessions.py -q`
Result: 12 passed. Full fast suite: see baseline (206 passed, 5 env-related
failures pre-existing; edge tests add 12 green).

## Method

Each edge shape constructs a `SessionAnalysis` directly (no PCAP) and runs
`run_rules()`. Assertion per rule: either a correct finding or silence /
`not_observable` — never a false HIGH/CRITICAL. `run_rules` traps per-rule
exceptions, so missing optional attributes degrade to skip, not crash.

## Matrix (rule x edge shape)

Edge shapes: zero-byte, aborted-after-ClientHello, reset-mid-handshake,
partial-missing-first-packets, duplicate/out-of-order, truncated-record,
ServerHello-only, implicit-port-no-bytes.

| Rule | zero-byte | aborted-CH | reset-mid | partial-nofirst | dup/reorder | truncated | SH-only | implicit-nobytes | Notes |
|---|---|---|---|---|---|---|---|---|---|
| tls-version-tls1-0/1-1 (HIGH) | silent | silent (0x0303) | silent | silent | silent | silent | silent | silent | needs weak version negotiated |
| weak-cipher / non-aead / non-pfs (LOW/MED) | silent | silent (AEAD/PFS offer) | silent | correct if weak meta present | silent (strong) | silent | silent (strong) | silent | needs cipher_meta |
| export/rc4/3des (CRIT/HIGH/MED) | silent | silent | silent | silent | silent | silent | silent | silent | synthetic-only (Task 7); no real handshake |
| cert rules (expired/self/untrusted/weak-sig/short-key) | silent | silent (no certs) | silent | silent | silent | silent | silent | silent | need usable certs; TLS1.3 blind → not_observable |
| plaintext-mail-protocol (HIGH) | silent (guard `plaintext_bytes>0`) | silent (has TLS bytes) | silent (0 bytes) | silent | silent | silent | silent | silent | zero-byte fix verified |
| starttls-strip-attempt (CRIT) | silent (no offer) | silent (TLS followed) | silent | silent | silent | silent | silent | silent | needs offer without TLS |
| no-tls-on-implicit-port (CRIT) | silent (guard) | n/a (has TLS) | silent | n/a | n/a | silent | n/a | silent (guard) | needs implicit port + bytes, no TLS |
| tls-handshake-incomplete (MED) | silent (no TLS bytes) | silent (CH present) | MEDIUM (correct) | silent (SH present, CH missing but cipher known — emits nothing; acceptable) | silent | MEDIUM (correct) | silent (SH present) | silent | never HIGH; MEDIUM is correct insuff-data signal |
| unknown-cipher (MED) | silent | silent | silent | silent (known) | silent | silent | silent | silent | needs unknown IANA |
| deprecated-group / no-modern-pfs / downgrade / hrr / tls-downgrade / ech / outdated / compression | silent | silent (modern offer) | silent | silent | silent | silent | silent | silent | need CH/SH fields |
| client-no-pfs-suites (LOW) | silent | silent | silent | silent | silent | silent | silent | silent | needs pre-1.3 + RSA-only offer |

No false HIGH/CRITICAL on any edge shape. No real bugs found beyond the
already-fixed zero-byte guard; the audit is preventive.

## Fuzz/property coverage

Existing property tests (`test_phase4_ja4.py` fuzz, `test_phase4_tls13.py`
arbitrary-bytes, `test_stage6_robustness.py` malformed/truncated) cover
parser-level never-raise. Rule-level edge shapes above are deterministic
complements; no new fuzz harness added (hypothesis already used by existing
tests where installed).

Last verified: 2026-10-10, Python 3.13, `test_edge_sessions.py` 12 passed.
