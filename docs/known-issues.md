# Known issues (blocker-closure lab, 2026-10-05)

FAIL or limitation entries discovered while closing v1.0 blockers. Each item:
observed behavior, impact, and status. Nothing here is guessed.

## 1. diff_tshark.py misses ServerHello ciphers (tooling, open)

`scripts/diff_tshark.py` reads tshark JSON field `tls.handshake.ciphersuite`,
which is empty for TLS 1.3 ServerHello (and some TLS 1.2). It reports
"tshark found no ciphers but we did" on every completed handshake. Direct
tshark queries agree with our parser everywhere checked
(`0x11ec`=4588, `0x001d`=29, `0x002f`, `0xc030`). Impact: noisy diff output
only; no product behavior. Fix: query version-appropriate fields.

## 2. hostname-mismatch has no live coverage (open, needs owner)

`validate_chain` returns chain errors before reaching the hostname check, so
a lab-CA wrong-host cert yields `untrusted-certificate-chain` only (correct).
The `hostname-mismatch` path needs a publicly-trusted wrong-name cert, which
only the owner can arrange. Labeled `present:false` with rationale in the
wronghost manifest entry.

## 3. Reassembly drops FIN-less streams silently (accepted limitation)

`StreamAssembler.emit()` skips streams without RST or dual-FIN. Captures cut
mid-connection lose those sessions entirely (no finding, no error). Lab
harnesses close deterministically so committed captures parse fully. Revisit
only on pilot demand: emitting partial streams would change session counts
across the corpus, ML features, and flows.

## 4. JA4S verified against reference code, not a numeric vector (accepted)

The JA4S spec is diagram-only; our layout matches the reference
implementation's `to_ja4s` behavior (GREASE included in count+hash). No
official numeric JA4S vector exists to test against. See
`docs/evidence/ja4-verification.md`.
