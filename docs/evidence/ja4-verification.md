# Item 1 evidence: JA3/JA4/JA4S verification (2026-10-05)

Analyst: lab run on this machine. Sources (read-only, nothing copied):

- Spec: `https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/technical_details/JA4.md`
  (retrieved 2026-10-02, re-retrieved 2026-10-05; 220 lines).
- Reference implementation: `python/ja4.py` (`to_ja4s`, `to_ja4`) and
  `python/common.py` (`get_hex_sorted`, `sha_encode`, `first_last_alpn`)
  from `https://github.com/FoxIO-LLC/ja4` (read 2026-10-05, not copied).
- License: FoxIO License 1.1 (non-commercial only). Because CipherPost's
  own license is undecided, **no spec text, code, or vectors were copied
  into this repo**. Only short factual input/output strings were used for
  local comparison. Our implementation remains self-derived.

## Method

1. Fed the spec's full worked example inputs (15 ciphers, 16 extensions,
   8 signature algorithms, SNI present, ALPN `h2`, TLS 1.3) into our
   `ja4()` and compared against the spec's printed fingerprint.
2. Read the reference `to_ja4`/`to_ja4s`/`get_hex_sorted` logic and
   compared each rule against ours (GREASE, counts, ordering, SNI/ALPN
   exclusions, sigalg gating, empty-list sentinels, ALPN fallback).
3. Recorded every divergence; fixed the real one (JA4S GREASE).

## Results

| Case | Result | Detail |
|---|---|---|
| JA4 full worked example | **MATCH** | `t13d1516h2_8daaf6152771_e5627efa2ab1` — version, SNI flag, counts (15/16), ALPN, both hashes. Test: `test_ja4_matches_official_spec_worked_example` |
| JA4 cipher hash (sorted, GREASE ignored, SCSV kept) | **MATCH** | Spec §Cipher hash rules identical to ours |
| JA4 ext hash (sorted, SNI+ALPN removed, sigalgs appended in order) | **MATCH** | Spec §Extension hash rules identical to ours |
| JA4 counts exclude GREASE | **MATCH** | Both sides |
| JA4 empty-list `000000000000` sentinels | **MATCH** | Both sides |
| JA4 sigalgs only when ext 13 present | **MATCH (equivalent)** | Reference gates on `0x000d` in extensions; we parse sigalgs only from ext 13, so identical outcomes |
| JA4S layout `{t}{ver}{exts:02d}{alpn}_{cipher}_{exthash}` | **MATCH** | Present-order ext hash, single embedded cipher |
| JA4S GREASE in count + hash | **MISMATCH found → FIXED** | Reference `to_ja4s` comment "include grease values"; old code stripped GREASE. Fixed in `ja4.py:ja4s`; test `test_ja4s_includes_grease_per_reference` fails before, passes after |
| JA4S empty extensions → `000000000000` | **MATCH** | Both sides |
| ALPN non-ASCII endpoints | **DIVERGENCE (kept, documented)** | Spec text prescribes hex rules (`0xAB`→`ab`); reference *code* substitutes `9`. We follow the spec text. ASCII ALPN (all real mail cases) is identical either way |
| JA3 construction | **PASS (structural)** | Five-field order-sensitive form + md5 verified by construction test; no official vector exists for our inputs, so this is not claimed as independent verification |
| JA3S construction | **PASS (structural)** | Same basis as JA3 |

## Bugs fixed

- JA4S dropped GREASE from count/hash contrary to reference behavior. Fix:
  keep present-order extensions including GREASE (`backend/app/parsing/ja4.py`).

## Remaining limits

- No official JA4S numeric vector exists (spec is diagram-only); JA4S is
  verified against reference *code behavior*, not an independent vector.
- Non-ASCII ALPN follows spec text over reference code by deliberate,
  documented choice.
- Reference code itself was only read, never executed (needs its tshark
  pipeline); behavior comparison is by code reading.

## Re-verification 2026-10-09 (cleanup Task 4)

Sources re-fetched (read-only, FoxIO License 1.1 still in force — nothing
copied): `technical_details/JA4.md` (220 lines, last change 820ec30 on
2026-01-21), `python/ja4.py` (610 lines, last change 9cfecc5 on 2026-09-22),
`python/common.py` (`sha_encode`, `first_last_alpn` unchanged in behavior).

- Spec text: JA4.md is client-fingerprint-only; no JA4S/server section
  exists, so the spec text is ambiguous for JA4S GREASE handling. (The
  "ignore GREASE" lines — §§ Details, cipher/extension counts — all sit in
  the client-fingerprint context.)
- Reference code `to_ja4s`: unchanged — `ext_len` counts all extensions
  with the verbatim comment "include grease values"; present-order sha12
  over the unfiltered list; single embedded cipher; `000000000000` when
  empty. Our `ja4s()` matches on every point.
- Decision (no guessing): behavior stays behind the named constant
  `JA4S_INCLUDE_GREASE = True` in `backend/app/parsing/ja4.py`, following
  the reference implementation. Claim level, stated in code and here:
  **verified against reference code only, spec text ambiguous**.
