# Live-run lab setup (docker-mailserver + CipherPost)

Stand up a small, real mail environment and a CipherPost capture on one VPS
or home server. The lab is for verifying detections against **known
configuration** — it is not production, and nothing here is a live-run result.

## What you get

- `docker-mailserver` (Postfix + Dovecot): SMTP 25, submission 587, SMTPS 465,
  IMAPS 993, POP3S 995, IMAP 143, POP3 110 — all bound to **127.0.0.1 only**.
- A CipherPost stack (capture, API, Postgres, Redis) on the same compose
  network, capture with only `NET_RAW`+`NET_ADMIN` (never `privileged`).
- Three selectable profiles so every detection class can be checked against
  known-good and known-bad configuration:

| Profile | Config | Expected detections |
|---|---|---|
| `modern` | TLS 1.2+, secure ciphers (`TLS_LEVEL=modern`) | none (clean baseline) |
| `legacy-tolerant` | TLS 1.0/1.1 re-enabled via `config/legacy-tolerant/postfix-main.cf` | protocol-version findings on SMTP |
| `deliberately-broken` | expired cert, weak ciphers, plaintext AUTH (`config/deliberately-broken/postfix-main.cf`) | expired-certificate, weak-cipher, plaintext evidence |

## Prerequisites

- Docker + docker compose plugin (any recent version).
- ~2 GB free disk (postgres, redis, DMS, CipherPost images).
- `openssl` CLI (for `scripts/lab_certs.sh`).

## One command

```bash
cd deploy/live-run
bash start_lab.sh modern            # or legacy-tolerant | deliberately-broken
```

The script:

1. generates the lab CA + `good`/`expired` server certs into `./certs`
   (via `scripts/lab_certs.sh`, self-signed, lab-only) if missing;
2. `docker compose --env-file profiles/<profile>.env up -d --build`;
3. creates two lab accounts (`alice@lab.test`, `bob@lab.test`) inside the
   container with **random passwords that are printed once and never
   committed**;
4. runs `smoke_test.py` (all mail ports + the CipherPost API).

## Sending test messages (all traffic stays on 127.0.0.1)

With the API up, sessions and findings appear in the dashboard
(`http://127.0.0.1:8000`). Local lab-to-lab mail:

```bash
# plaintext submission (deliberately-broken only; modern/legacy-tolerant
# have smtpd_tls_auth_only=yes so AUTH requires TLS)
printf 'EHLO lab\r\nMAIL FROM:<alice@lab.test>\r\nRCPT TO:<bob@lab.test>\r\nQUIT\r\n' | nc 127.0.0.1 25

# TLS to SMTPS with the lab CA (verifies modern/legacy-tolerant TLS works)
openssl s_client -connect 127.0.0.1:465 -quiet -CAfile certs/ca.crt \
  -servername mail.lab.test <<'EOF'
EHLO lab
MAIL FROM:<alice@lab.test>
RCPT TO:<bob@lab.test>
QUIT
EOF

# expired-cert behavior (deliberately-broken): expect verification failure
openssl s_client -connect 127.0.0.1:465 -brief -CAfile certs/ca.crt \
  -servername mail.lab.test </dev/null; echo "exit=$?"
```

## TLS certificates: lab vs real domain (clearly separated)

**Lab (this directory, default):** `scripts/lab_certs.sh` generates a 30-day
lab CA and server certs (`good`, `expired`, `wronghost`, `self`, `weak`) in
`./certs`. The `expired` pair is expired **from the moment of generation**
(`-days 0`). Lab certs must never be used outside loopback testing.

**Real domain (NOT covered by the lab profile files):** for a real
deployment on a real domain, use Let's Encrypt instead of the lab CA:

```bash
certbot certonly --standalone -d mail.example.com
# then point the env file at the real paths:
#   SSL_CERT_PATH=/etc/letsencrypt/live/mail.example.com/fullchain.pem
#   SSL_KEY_PATH=/etc/letsencrypt/live/mail.example.com/privkey.pem
```

and mount `/etc/letsencrypt` read-only into the mail container. Renewal
(deploy hook restarting the container) is the operator's responsibility —
see `docs/live-run/ops-checklist.md` for the expiry checks CipherPost itself
should be watched with.

## Honest limits (read before drawing conclusions)

- **A lab with no real internet traffic is not production.** The lab proves
  the pipeline detects what it was built to detect under controlled
  configuration; it says nothing about precision on real mail flows. That is
  what the 30-day run and pilot feedback are for.
- DMS v12+ removed TLS 1.0/1.1 from `TLS_LEVEL=intermediate`; the
  legacy-tolerant profile re-enables them for **SMTP only** via a documented
  Postfix override. IMAP/POP3 legacy TLS would additionally need a Dovecot
  override (not part of this profile — add only if you need that detection).
- Modern OpenSSL in the image may refuse `export` ciphers entirely; if
  `deliberately-broken` fails to start with cipher errors, that is the
  expected collision between "weak config" and "modern library" — record it
  in the daily log instead of working around it silently.
- Capturing docker bridge traffic has NAT/visibility caveats — read
  `docs/live-run/capture-placement.md` before trusting "no sessions".

## Privacy defaults

- Everything binds to 127.0.0.1; no third-party mail server is contacted.
- Lab account passwords are random at creation and never committed; the
  fixed lab secret values in `profiles/*.env` are labeled lab-only and the
  API runs with `CIPHERPOST_ENV=dev`.
- Captures on this network still contain handshakes and protocol bytes —
  keep raw-capture retention short (`RAW_RETENTION_SECONDS`) and delete
  `maildata` when the lab is torn down (`docker compose down -v`).
