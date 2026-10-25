#!/usr/bin/env bash
# Start the CipherPost live-run lab (one command).
# Usage: bash start_lab.sh [--profile modern|legacy-tolerant|deliberately-broken]
set -euo pipefail

cd "$(dirname "$0")"

PROFILE="modern"
if [[ "${1:-}" == "--profile" && -n "${2:-}" ]]; then
    PROFILE="$2"
fi

echo "[*] Starting CipherPost lab (profile: $PROFILE)..."
docker compose --profile "$PROFILE" up -d

echo "[*] Waiting for services to boot (15s)..."
sleep 15

echo "[*] Running smoke test..."
python3 smoke_test.py
