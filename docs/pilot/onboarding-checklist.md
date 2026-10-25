# Pilot onboarding checklist (pre-1.0, use as-is only with counsel-reviewed agreement)

For onboarding one pilot organization onto CipherPost. This checklist uses
only install paths that are actually documented in this repository
(`docker/docker-compose.yml` or `deploy/helm/cipherpost`) and only measured
numbers from `docs/sizing.md`. Nothing here is a product commitment.

## 0. Prerequisites (confirm BEFORE the install hour)

- [ ] **Authorization confirmed in writing**: the pilot's security owner has
      signed/reviewed the data-handling summary
      (`docs/pilot/data-handling-summary.md`) and the agreement outline has
      been through **their** counsel (`pilot-agreement-outline.md` is a
      non-legal starting point, not an agreement).
- [ ] **Capture point chosen** and physically/logically available:
      SPAN/mirror port or TAP feeding the mail VLANs, or a host-mode /
      sidecar placement per `docs/live-run/capture-placement.md`. The pilot
      must understand what their placement can and cannot observe (TLS 1.3
      certificate blindness is expected and documented).
- [ ] **Contacts exchanged**: pilot analyst (day-to-day), pilot security
      owner (escalation), and our support contact. Weekly check-in slot
      booked (`weekly-checkin-template.md`).
- [ ] **Sizing from measured numbers only** (`docs/sizing.md`): the only
      measured figures are toy-corpus replay numbers (~28k packets/s,
      ~24k sessions/s, RSS ~48 MB, 1-min soak 0 errors on a Ryzen 7
      5700G). **Do not size production from them.** Minimum evaluation
      footprint: 4 vCPU / 8 GB RAM + the pilot's own 10-minute replay test
      (`scripts/load_test.py`) before commit.
- [ ] **Pre-flight run on the pilot host**: `python
      scripts/pilot_preflight.py` — all FAIL items resolved (see its
      output explanations; it sends nothing anywhere).
- [ ] **Retention + deletion agreed**: retention days to configure
      (defaults in `DEPLOYMENT.md` Data lifecycle), who can trigger
      deletion, and what "delete everything" means for the pilot
      (see `data-handling-summary.md`).

## 1. One-hour install (compose path — the documented evaluation path)

All commands on the pilot-provided Linux host, from a clone of this repo.

```bash
# minutes 0-10: clone + secrets
git clone <repo> && cd CipherPost
cp .env.example .env
# fill in (never commit .env):
#   POSTGRES_PASSWORD   openssl rand -hex 24
#   CIPHERPOST_JWT_SECRET  openssl rand -hex 32
#   CIPHERPOST_ADMIN_PASSWORD  (>= 12 chars, rotate after first login)

# minutes 10-30: build + boot
docker compose -f docker/docker-compose.yml up --build -d
# (no capture privileges needed for a replay-only first session:
#  docker compose -f docker/docker-compose.yml --profile replay up --build)

# minutes 30-40: verify
docker compose -f docker/docker-compose.yml ps            # all healthy
python scripts/pilot_preflight.py --post-install          # PASS/WARN/FAIL
```

## 2. Verification (must pass before the pilot "starts")

- [ ] `cipherpost doctor` reports PASS on: DB reachable, migrations at
      head, disk headroom, clock sync, log rotation configured
      (see `docs/live-run/ops-checklist.md` for what doctor covers).
- [ ] Log in as bootstrap admin → **create per-operator accounts → rotate
      the bootstrap password** (per `docs/pilot-guide.md`).
- [ ] Configure **one** alert channel; send one test alert.
- [ ] Replay a fixture or upload a PCAP: sessions + findings appear in
      `/app/live` (this proves the analysis path end to end).
- [ ] If live capture is part of the pilot: run the **both-directions
      checklist** in `docs/live-run/capture-placement.md` and only then
      start the capture container.
- [ ] **Smoke test**: `deploy/live-run/smoke_test.py --host <api-host>`
      (or the lab flow in `docs/live-run/setup.md` if the pilot also
      stands up the mail lab) — all checks PASS.
- [ ] First weekly data point captured with `docs/pilot/pilot-metrics.md`.

## 3. During the pilot

- Weekly check-ins (`weekly-checkin-template.md`), findings labeled via the
  feedback flow (provenance is exported by `scripts/export_labels.py`).
- Operational problems → issue bundle + ops issue template
  (`docs/live-run/triage.md` severity scale).
- Any suspected false positive / missed detection →
  `docs/live-run/triage.md` confirmation steps BEFORE labeling.

## 4. Exit

- End-of-pilot survey (`end-of-pilot-survey.md`).
- Data deletion executed and confirmed (`data-handling-summary.md`
  "Delete everything"); deletion receipt noted in the pilot record.
- Lessons learned appended to the pilot record (facts only, no metrics
  published without the pilot's written OK).
