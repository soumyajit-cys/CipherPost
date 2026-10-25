# Evidence: pilot kit + preflight (Task 5, 2026-10-25)

Branch `live-run-kit`. No pilot exists; no pilot data is claimed anywhere.

## Preflight run against this host (real output, unedited except truncation)

Command: `python scripts/pilot_preflight.py --capture-target 127.0.0.1:1`
(127.0.0.1:1 deliberately dead — validates the FAIL path on a real host.)

```
[PASS] os/arch              Linux x86_64 (6.19.11+kali-amd64)
[FAIL] container-runtime    docker installed but daemon unreachable: permission denied
                            ... docker.sock ...
[WARN] kubernetes           kubectl not found (only needed for the Helm path)
[WARN] ports                ports already in use on 127.0.0.1: 5432, 6379 — ...
[PASS] disk                 164.8 GB free at .
[PASS] clock-sync           timedatectl: NTP synchronized
[WARN] capture-permissions  cannot open a raw capture socket ([Errno 1] Operation not permitted) ...
[PASS] dns                  resolved: localhost
[FAIL] capture-path         127.0.0.1:1 not reachable from this host
2 FAIL, 3 WARN, 4 PASS
```

Matches the intended semantics: docker-socket permission and a dead
capture target FAIL; k8s/capture-perms WARN (optional paths); NTP
synchronization detected via `timedatectl`.

## Tests

`PYTHONPATH=backend/. python -m pytest backend/tests/test_pilot_preflight.py
backend/tests/test_live_run_lab.py -q` → **25 passed**. Simulated failures
cover: daemon down, binary missing, no k8s cluster, busy ports, low/absent
disk, no NTP tooling, missing CAP_NET_RAW, bad DNS, unreachable/dead
capture path, API down/down-status, check-crash containment, CLI exit 1.

## NOT-VERIFIED

- Preflight on a real pilot host with Kubernetes access (no cluster here);
  the k8s check is simulated only.
- The full pilot flow (checklist → install → doctor → smoke) end to end:
  requires a container runtime this environment cannot use.
