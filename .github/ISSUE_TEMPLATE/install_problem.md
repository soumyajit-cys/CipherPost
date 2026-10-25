---
name: Install problem
about: Something fails while installing or first-booting CipherPost
title: "[install] <step that failed>"
labels: install
---

## Which install path

- [ ] docker compose (`docker/docker-compose.yml` or `deploy/live-run/`)
- [ ] Helm chart (`deploy/helm/cipherpost`)
- [ ] systemd agent (`deploy/systemd/cipherpost-agent.service`)
- [ ] offline CLI (`pip install cipherpost`)

## Exact command and full error output

```
<paste the command and the error, redacting secrets>
```

## Expected behavior

What should have happened at this step (e.g. "migrate completes to head",
"capture starts and `cipherpost doctor` passes").

## Preflight output (if you ran it)

Attach `python scripts/pilot_preflight.py` output — it is local-only.

## Evidence bundle (required)

```bash
python scripts/export_issue_bundle.py --install
# or, from a running instance:
curl -s .../api/v1/diagnostics/bundle > diagnostics.json
```

## Environment

- OS and version (`uname -a`):
- CipherPost version / image tag:
- Docker / K8s versions if applicable:
