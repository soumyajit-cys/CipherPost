# Evidence: live-run lab kit (Task 1, 2026-10-25)

Branch `live-run-kit`. What ran, what did not, and the doc basis for every
externally-visible choice. No live-run or pilot claim is made here.

## docker-mailserver documentation basis

Retrieved 2026-10-25 (webfetch of the official docs, edge channel):

| Fact used | Source URL | Where used |
|---|---|---|
| Image name `ghcr.io/docker-mailserver/docker-mailserver` (alt `docker.io/mailserver/docker-mailserver`) | https://docker-mailserver.github.io/docker-mailserver/edge/usage/ | `deploy/live-run/docker-compose.yml` `image:` |
| Config volume: host `docker-data/dms/config/` → container `/tmp/docker-mailserver/` | same usage page ("a volume mounts the host location docker-data/dms/config/ to /tmp/docker-mailserver/ inside the container") | mount `./config/<profile>/:/tmp/docker-mailserver/` |
| `SSL_TYPE=manual` requires `SSL_CERT_PATH` + `SSL_KEY_PATH` (paths inside the container); `letsencrypt` for real domains | https://docker-mailserver.github.io/docker-mailserver/edge/config/environment/ (§SSL_TYPE) | env block + profile env files |
| `TLS_LEVEL`: `empty`/`modern` = secure ciphers only; `intermediate` = relaxed; **v12.0+ dropped TLS 1.0/1.1 from intermediate** (workaround needed for legacy) | same page (§TLS_LEVEL, note verbatim) | profile env files + `config/legacy-tolerant/postfix-main.cf` |
| `ENABLE_IMAP` / `ENABLE_POP3` enable those protocols (ports 143/110) | same page (§ENABLE_IMAP, §ENABLE_POP3) | env block + published ports |
| Port meanings 25/587/465/993/995 | https://docker-mailserver.github.io/docker-mailserver/edge/config/security/understanding-the-ports/ (structure of the docs; port roles cross-checked against the usage page) | port comments |

The override-file mechanism (drop-in `postfix-main.cf` inside the config
volume) is the documented "Override the Default Configs → Postfix" path
(usage page section list, retrieved 2026-10-25).

## What ran here (with commands + versions)

Tool versions: Python 3.13.12, OpenSSL 3.6.1 (27 Jan 2026), Docker CLI 29.x
(daemon **not accessible** — see NOT-VERIFIED below), GNU bash 5.x.

1. **Compose validation, all 3 profiles:**
   `cd deploy/live-run && docker compose --env-file profiles/<p>.env config`
   → exit 0 for modern / legacy-tolerant / deliberately-broken; rendered
   env shows `TLS_LEVEL: modern|intermediate` and
   `SSL_CERT_PATH: /certs/good.crt|/certs/expired.crt` per profile; all
   published ports are `127.0.0.1:*`.

2. **Lab CA + certs actually generated:**
   `bash scripts/lab_certs.sh /tmp/opencode/labcerts`
   → produces `ca.crt, good.crt/key, expired.crt/key, wronghost.*, self.*,
   weak.*`; `openssl x509 -checkend 0` on `expired.crt` →
   "Certificate will expire" (exit 1) — the 0-day cert is genuinely expired
   at generation time (verified 2026-10-25 06:16 UTC, cert notAfter
   06:12:52Z same day). `good.crt` notAfter = +30 days, SAN
   `DNS:mail.lab.test`, CN `mail.lab.test` — names match what the profiles
   reference (`/certs/good.crt`, `/certs/expired.crt`).

3. **Unit tests for lab logic (no mail server needed):**
   `PYTHONPATH=backend/. python -m pytest backend/tests/test_live_run_lab.py -q`
   → **10 passed**: smoke-test pass/fail logic against a real loopback
   listener and a real local HTTP server (200/503/unreachable), profile env
   expectations, override-file expectations, loopback-only port binding,
   DMS image/SSL_TYPE presence, lab_certs.sh ↔ profile path consistency.

## NOT-VERIFIED (with what is missing)

- **Running the lab containers**: Docker daemon is present but this session
  cannot use it (`docker pull` → "permission denied … docker.sock"). Missing:
  daemon access. Until someone runs `bash deploy/live-run/start_lab.sh
  <profile>`, bring-up, account creation (`setup email add`), TLS behavior
  (expired cert rejection, plaintext AUTH on 587 via `openssl s_client` /
  swaks), and end-to-end finding appearance are NOT-VERIFIED.
- **Pinned DMS image tag**: the compose uses
  `ghcr.io/docker-mailserver/docker-mailserver:latest` via `DMS_IMAGE` env.
  Pinning requires pulling and running a specific tag against all three
  profiles — cannot be done here. **Pinning is required before real use**
  (keep the variable, set a real tag after a verified run).
- **Legacy-TLS handshake capture**: whether the SMTP-only override is enough
  for the detections the corpus expects (vs needing a Dovecot override) can
  only be confirmed with a running lab.
- **Weak ciphers in deliberately-broken**: modern OpenSSL in the DMS image
  may refuse `export` ciphers at startup; expected collision, documented in
  docs/live-run/setup.md — outcome unverifiable without the runtime.
