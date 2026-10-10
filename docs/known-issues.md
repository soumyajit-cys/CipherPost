# Known issues (blocker-closure lab, 2026-10-05; cleanup review 2026-10-10)

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
wronghost manifest entry. Cleanup 2026-10-10: exact trigger documented in
`docs/what-we-cannot-see.md` ("Hostname mismatch"), matching-logic unit test
added (`test_edge_sessions.py::test_hostname_matching_logic_unit`); end-to-end
live path stays NOT-VERIFIED for lack of a trusted-chain wrong-name cert —
no pipeline redesign in this task by design.

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

## 5. RC4/3DES/export rules have no real-handshake coverage (open, no infra)

Ciphers absent from OpenSSL 3.6, so no lab capture can negotiate them.
Cleanup 2026-10-10: synthetic unit fixtures added
(`test_edge_sessions.py::test_rc4_3des_synthetic_rule_logic`, clearly named
synthetic) exercising the rule logic; docs state these paths are NOT verified
on real handshakes (`docs/what-we-cannot-see.md` "Legacy ciphers"). Left open
because generating real RC4/3DES handshakes needs an old-OpenSSL/MTA build —
new infrastructure out of scope for this cleanup task.

## 6. Helm chart installs without a cluster (partially closed 2026-10-10)

`helm lint` + `template` + `kubeconform` now pass locally (18/18 valid;
fixed missing `---` separator in `templates/bundled.yaml` — see
`docs/evidence/helm-validation.md`). Installation remains NOT-VERIFIED until
the kind workflow runs. Unfixable-without-a-cluster items stay listed in
`docs/evidence/kind-install.md` (registry images/pull secrets, HPA behavior,
probe tuning, bundled auth/persistence, storageClassName, parity).
