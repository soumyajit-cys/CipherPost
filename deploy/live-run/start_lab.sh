#!/usr/bin/env bash
# Start the CipherPost live-run lab (one command).
# Usage: bash start_lab.sh [modern|legacy-tolerant|deliberately-broken]
set -euo pipefail

cd "$(dirname "$0")"

PROFILE="${1:-modern}"
case "$PROFILE" in
  modern|legacy-tolerant|deliberately-broken) ;;
  *) echo "unknown profile '$PROFILE' (use modern|legacy-tolerant|deliberately-broken)" >&2; exit 2;;
esac

LAB_USER="${LAB_USER:-alice}"
LAB_PASS="${LAB_PASS:-alice-lab-pass-$(openssl rand -hex 4 2>/dev/null || date +%s)}"
LAB_DOMAIN="${MAIL_DOMAIN:-lab.test}"

echo "[*] Profile: $PROFILE"

# Generate lab certs if missing (self-signed lab CA; loopback only, lab-only).
if [ ! -f certs/ca.crt ] || [ ! -f certs/good.crt ] || [ ! -f certs/expired.crt ]; then
  echo "[*] Generating lab certificates (scripts/lab_certs.sh -> ./certs)..."
  mkdir -p certs
  bash ../../scripts/lab_certs.sh certs
fi

echo "[*] Starting lab stack (docker compose, env: profiles/$PROFILE.env)..."
docker compose --env-file "profiles/$PROFILE.env" up -d --build

echo "[*] Waiting for services to boot (20s)..."
sleep 20

echo "[*] Creating lab accounts ($LAB_USER + bob) via docker-mailserver setup.sh..."
# DMS account management runs inside the container; passwords are random and
# never committed (docs/live-run/setup.md).
docker compose --env-file "profiles/$PROFILE.env" exec -T mail \
  setup email add "$LAB_USER@$LAB_DOMAIN" "$LAB_PASS" || echo "[!] account $LAB_USER failed"
docker compose --env-file "profiles/$PROFILE.env" exec -T mail \
  setup email add "bob@$LAB_DOMAIN" "bob-lab-pass-$(openssl rand -hex 4 2>/dev/null || date +%s)" || echo "[!] account bob failed"

echo "[*] Running smoke test..."
python3 smoke_test.py || echo "[!] smoke test reported failures (see above)"

echo
echo "[i] $LAB_USER password (used for submission tests; not stored anywhere):"
echo "    $LAB_PASS"
