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

echo "[*] Profile: $PROFILE"

# Generate lab certs if missing (self-signed lab CA; harmless, loopback only).
if [ ! -f ../certs/ca.crt ] || [ ! -f ../certs/good.crt ]; then
  echo "[*] Generating lab certificates (scripts/lab_certs.sh)..."
  mkdir -p ../certs
  bash ../../scripts/lab_certs.sh ../certs
fi

echo "[*] Starting lab stack (docker compose, profile env: profiles/$PROFILE.env)..."
docker compose --env-file "profiles/$PROFILE.env" up -d --build

echo "[*] Waiting for services to boot (20s)..."
sleep 20

echo "[*] Running smoke test..."
python3 smoke_test.py || echo "[!] smoke test reported failures (see above)"
