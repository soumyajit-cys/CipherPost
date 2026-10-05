# Item 5 evidence: chaos + soak on real services (2026-10-05)

Machine: 16 vCPU, 14 GB RAM (desktop box, ~13 GB in use by other apps during
runs), Python 3.13.12, local Redis 7 + Postgres (system services),
OpenSSL 3.6.1. Durations are stated; nothing extrapolated.

## Chaos suite (slow, real services where privileges allow)

`PYTHONPATH=backend python -m pytest backend/tests/test_phase2_chaos.py -q`
→ **7 passed** (6 pre-existing fakeredis/sqlite simulations + 1 new).

New (Item 5): `test_redis_real_outage_client_pause_buffers_and_redelivers`
— a REAL outage against the local Redis 7 server (`CLIENT PAUSE 12000`
stalls all clients; `DEBUG sleep` is disabled on hardened configs and
`enable-debug-command` needs a restart we cannot perform). Publisher buffers
5 entries with zero caller-visible errors during the stall, then redelivers
exactly 5 (stream length 3→8, no duplicates, depth back to 0). Unique stream
key per run, deleted afterwards. 12.4 s wall time.

Outcomes: no crash loops, no data loss beyond the documented bounded buffer
(no drops occurred: buffer never filled), no duplicate deliveries, no
unbounded growth (buffer cap 64 enforced by existing code path).

## Could NOT run (NOT-VERIFIED, with reasons)

- **True Postgres restart mid-stream**: PG runs as system user `postgres`;
  uid 1000 cannot signal it, and there is no container runtime (docker
  daemon down) to cycle. The existing `test_db_outage_then_recovery`
  simulates at the persist layer only.
- **Worker SIGKILL in containers**: no container runtime; process-level kill
  covered by design via consumer-group reclaim
  (`test_kill_analyzer_mid_message_no_loss_no_dup`, fakeredis).
- **Disk-full retention dir**: no mount privileges for small tmpfs; existing
  `test_disk_pressure_retention_stays_bounded` simulates with tmp_path.
- **Nightly CI workflow run**: cannot trigger or link a run from here; the
  workflow file itself is unchanged and still schedules the full suite.

## Soak (short, stated duration: 3 minutes)

`PYTHONPATH=backend python scripts/soak.py --minutes 3` (default fixture
corpus, looped reassembly+analysis with garbage-burst fault injection):

- loops=17733 packets=4628053 sessions=3954236 findings=1968252
- errors=0 faults=17733 elapsed=180.0s peak_rss=47.9MB
- throughput ≈ 25.7k packets/s on the above box. Toy-scale looped fixtures,
  not production traffic; see docs/sizing.md for how to size from your own
  replay. No crash loops, no memory growth (RSS flat at ~48 MB), every
  injected fault absorbed (faults counter == loops, errors == 0).

## Latency probe (rules stage only, lab corpus)

Per-session `run_rules` over all 94 `tests/real` sessions:
min=0.00ms p50=0.00ms p95=0.02ms max=0.02ms. Rules are sub-millisecond;
end-to-end packet-to-finding latency is dominated by reassembly/capture and
was NOT measured end-to-end here (no live sensor run in this task).

## Incidental finding (environment, not product)

During Item 3 debugging, ~4 GB of stray capture files accumulated on tmpfs
(this box) from never-killed manual capturers, plus 10–24 concurrent stray
AF_PACKET capturers. Under that self-inflicted pressure, loopback captures
showed selective gaps. After cleanup (tmpfs 56%→13%, zero stray capturers),
captures are complete and deterministic. Lesson recorded: keep lab capture
one-at-a-time and kill capturers by PID. No product change resulted.
