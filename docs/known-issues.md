# Known issues (blocker-closure lab, 2026-10-05)

FAIL or limitation entries discovered while closing v1.0 blockers. Each item:
observed behavior, impact, and status. Nothing here is guessed.

## 1. diff_tshark.py comparison gaps (tooling, fixed 2026-10-09)

Root causes found and fixed (not just "field artifact"): the script read
`pkt["layers"]` instead of `pkt["_source"]["layers"]` (all comparisons ran
on empty rows), used a nonexistent `extensions_supported_version` field
(correct: `extensions.supported_version`), and compared whole-file string
sets across encodings. After the fix, `scripts/diff_tshark.py tests/real/`
reports 28/28 agree (`docs/evidence/diff-tshark.md`). Remaining gap:
tshark leaves some Certificate messages as raw bytes (no `x509sat`
subjects); that case is now "cannot compare", with CN correctness covered
by openssl cross-checks at cert creation.

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
