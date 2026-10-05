# Item 2 evidence: post-quantum interop (2026-10-05)

Lab only. No third-party servers contacted. All captures are lab-generated
TLS handshakes (see `tests/real/manifest.json`, license CC0).

## Toolchain (exact versions)

- `openssl version` → `OpenSSL 3.6.1 27 Jan 2026`
- `openssl list -kem-algorithms` includes `X25519MLKEM768`,
  `SecP256r1MLKEM768`, `X448MLKEM1024`, `ML-KEM-512/768/1024`
- `tshark -v` → `TShark (Wireshark) 4.6.4`
- `dumpcap` on `lo` (has cap_net_raw); captures filtered to
  `tcp.port==465`, rewritten `-F pcap` (classic pcap: dpkt cannot read
  pcapng — noted, not a product bug)
- Lab CA + server cert (RSA 2048, CN mail.pqlab.test, 2-day validity),
  SMTPS-style implicit TLS on 127.0.0.1:465

## Cases (all captured, all parsed, all cross-checked vs tshark)

| Capture | Setup | tshark decode | Our parser | Verdict |
|---|---|---|---|---|
| `pq_hybrid_lab_01.pcap` | both `-groups X25519MLKEM768` | offered [0x11ec], selected 4588 | offered [hybrid PQ], selected same, negotiated_pq true | AGREE |
| `pq_classic_lab_01.pcap` | both `-groups X25519` | offered [0x001d], selected 29 | offered [x25519], selected x25519 | AGREE |
| `pq_gap_lab_01.pcap` | server X25519, client `X25519MLKEM768:X25519` | offered [0x11ec,0x001d], selected 29, HRR present | offered_pq true, negotiated false, hrr true | AGREE |
| `pq_hrr_lab_01.pcap` | server X448, client `X25519:X448` | HRR → 2nd ClientHello → SH, selected 30 | selected x448, hrr true | AGREE |
| `pq_no_overlap_lab_01.pcap` | server X448, client X25519 | fatal Handshake Failure, no SH | no findings, no invented data | AGREE |

Note: the `pq_gap` HRR was initially misread by the analyst as
"no-HRR"; tshark showed the HRR and the parser was right (`hrr: true`).
The parser corrected the analyst, not vice versa.

## Bug found and fixed

`parse_server_hello` required `len(key_share_ext) == 2`, but a real TLS
1.3 ServerHello key_share is `group + key_exchange` (e.g. 1218 bytes for
X25519MLKEM768). Result: `selected_group` was None for every real
ServerHello; only HRR messages (bare 2-byte group) parsed. Fix: accept
`len >= 2`, read group from first u16 (`backend/app/parsing/handshake.py`).
Regression test `test_server_keyshare_with_key_exchange_bytes_selects_group`
fails before, passes after (verified via `git stash`).

## diff_tshark.py note (tooling artifact, not a product disagreement)

`scripts/diff_tshark.py` reported "tshark found no ciphers but we did" on
all four completed handshakes: it reads `tls.handshake.ciphersuite`, which
is empty for TLS 1.3 ServerHello in tshark JSON. Direct query shows
`tshark: 0x1302` = our `TLS_AES_256_GCM_SHA384`. Agreement confirmed
manually; diff script improvement left as follow-up (see known-issues).

## eval_real.py

`PYTHONPATH=backend python scripts/eval_real.py tests/real/manifest.json` →
5 captures, 5 sessions, 0 misses, 0 false positives on labeled rules.
Labels were written from server configuration (not tool output); all
findings-free expectations held, including the abort negative control.
