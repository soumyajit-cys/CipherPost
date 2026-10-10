# Task 3 evidence: diff_tshark.py root causes and re-run (2026-10-09)

Tool versions: TShark 4.6.4, Python 3.13. Command:
`PYTHONPATH=backend python scripts/diff_tshark.py tests/real/`
Result 2026-10-09: **28/28 agree, zero disagreements.**

## Actual causes found (not just "field artifact")

1. **Wrong JSON path**: script read `pkt["layers"]`; tshark `-T json -e`
   nests fields under `pkt["_source"]["layers"]` with list values. Every
   comparison ran on empty rows — the "tshark found no ciphers" messages
   were the script comparing against nothing. Fixed with `_layers()` +
   `_one()` unwrapping (`backend/tests/test_diff_tshark.py::
   test_layers_unwrap_and_hex`).
2. **Wrong field name**: `tls.handshake.extensions_supported_version`
   does not exist (tshark errors, output empty). Correct name per
   `tshark -G fields`: `tls.handshake.extensions.supported_version`
   (verified: yields `0x0304` on both hellos of the PQ capture).
3. **Whole-file set comparison**: version strings (`771` vs `"0x0303"`)
   and cipher names vs hex could never match structurally. Replaced with
   per-ServerHello (version-int, cipher-name) pairs; ours cipher names map
   via `lookup_cipher`, versions compare as ints with the
   supported_version-first/legacy-fallback rule. HRR's bare key-share hello
   contributes no pair on either side.
4. **Cert subjects**: tshark leaves some Certificate messages as raw bytes
   (no `x509sat` subjects) while our DER parser reads CN correctly
   (cross-checked against openssl at cert creation). Absence of tshark
   subjects is now "cannot compare", not disagreement
   (`docs/known-issues.md` item 1 updated accordingly below).

## Re-run result

28/28 captures agree (table in output above; per-capture session and
tshark-row counts printed by the script). No remaining real disagreements;
no parser bug indicated. The previously reported disagreements were all
script-side.

Re-run 2026-10-10 (cleanup review): `tshark -v` → TShark 4.6.4, same command
— 28/28 agree, zero DISAGREEMENTS lines (per-capture `agree
(sessions=N tshark_rows=M)` for all 23 mail + 5 PQ captures). No new parser
bug indicated.

## Follow-up change to known-issues.md

Item 1 is now: script fixed; remaining `x509sat` gap documented as
unconfirmable-by-script (correctness covered by openssl cross-checks).
