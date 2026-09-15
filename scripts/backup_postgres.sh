#!/usr/bin/env bash
# CipherPost PostgreSQL backup (track 6).
# Findings/session history is the valuable long-term asset: back it up.
#
# Usage:
#   scripts/backup_postgres.sh [backup_dir]     # uses $PG* env or defaults
#   scripts/backup_postgres.sh /backups restore <file.dump>
#
# Keeps the 14 most recent dumps in the target dir. For point-in-time
# recovery, enable WAL archiving on the Postgres server (see DEPLOYMENT.md).
set -euo pipefail

BACKUP_DIR="${1:-/backups/cipherpost}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-cipherpost}"
PGDATABASE="${PGDATABASE:-cipherpost}"
KEEP="${BACKUP_KEEP:-14}"

if [[ "${1:-}" == "restore" ]]; then
  DUMP="${2:?usage: backup_postgres.sh restore <file.dump>}"
  echo "Restoring $DUMP into $PGDATABASE@$PGHOST (drops + recreates)..."
  pg_restore --clean --if-exists -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
    -d postgres -C "$DUMP"
  echo "restore complete"
  exit 0
fi

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/cipherpost-$STAMP.dump"
echo "Backing up $PGDATABASE@$PGHOST -> $OUT"
pg_dump -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -Fc -f "$OUT" "$PGDATABASE"
ls -1t "$BACKUP_DIR"/cipherpost-*.dump | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup complete: $OUT"
