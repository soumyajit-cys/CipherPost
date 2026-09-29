# Sizing guide — measured numbers only

Machine spec for every number below: AMD Ryzen 7 5700G (16 threads), 14 GB
RAM, local SSD, Python 3.13 venv. Command:
`PYTHONPATH=backend python scripts/load_test.py tests/fixtures`
(in-process replay: LiveReassembler + analyze_session, no Redis/Postgres).

## Measured (2026-09-30, synthetic corpus: 16 PCAPs, 261 packets, 184 KB)

| Metric | Measured |
|---|---|
| Packets | 261 in ~0.01 s → **~28,000 packets/s** |
| Sessions analyzed | 223 → **~24,000 sessions/s** |
| Findings emitted | 276 |
| Packet-to-analysis latency p50 / p95 / p99 | **~8 µs / ~19 µs / ~26 µs** |
| Peak RSS | **~48 MB** |

## Soak (2026-09-30, `scripts/soak.py --minutes 1`, same machine)

| Metric | Measured |
|---|---|
| Loops over corpus | 6,955 in 60.0 s |
| Packets / sessions / findings | 1,815,152 / 1,550,877 / 1,919,484 |
| Errors | **0** (6,955 garbage-packet faults injected, all survived) |
| Peak RSS | **47.6 MB (flat — bounded)** |

Caveat: loops re-feed identical packets, so session counts are stress volume,
not unique flows. A 24-hour run on live SPAN traffic is still required before
any production claim (see Task 8 notes in the Phase 2 report).

## What this does NOT prove (read before sizing production)

- The corpus is tiny (261 packets) and synthetic: per-packet cost is
  dominated by Python overhead, not representative TLS handshakes at scale.
- No Redis, Postgres, ML scoring (RollingBaseline refit), SHAP, PDF, or
  network capture overhead is included — the live pipeline adds all of these.
- No Mbps figure is given because total input bytes (184 KB) make any
  conversion noise. **Do not extrapolate these numbers to link sizing.**

## Estimates (clearly marked, not measured)

- *Estimate:* K8s requests in `k8s/backend.yaml` assume ~200 sessions/min per
  analyzer replica including TLS parse + rules + ML + SHAP. This is an
  engineering estimate carried over from Phase 1, not a measurement.
- *Estimate:* capture memory is bounded by `LIVE_MAX_SESSIONS` (4096) ×
  `LIVE_MAX_SESSION_BUFFER_BYTES` (512 KiB) worst case; typical use is far lower.

## How to measure your own traffic

1. Capture 10+ minutes of SPAN traffic: `tcpdump -w sample.pcap 'tcp port 25 or ...'`
2. `PYTHONPATH=backend python scripts/load_test.py sample.pcap --rate 5000`
3. Compare `sessions_per_s` against analyzer replicas (HPA target CPU 70%).
4. Soak: see Task 8 soak script notes in the final report.
