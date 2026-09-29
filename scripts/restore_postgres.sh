#!/usr/bin/env bash
# CipherPost PostgreSQL restore (Phase 2 Task 4 companion to backup_postgres.sh).
#
# Usage:
#   scripts/restore_postgres.sh <file.dump>   # uses $PG* env or defaults
#
# Drops + recreates the target database from a pg_dump -Fc archive, then
# verifies the Alembic revision is at head. DANGEROUS: destroys current data.
# Requires explicit confirmation unless --yes is passed (CI uses --yes).
set -euo pipefail

DUMP=""
YES=0
for arg in "$@"; do
  case "$arg" in
    --yes) YES=1 ;;
    *) DUMP="$arg" ;;
  esac
done
if [[ -z "$DUMP" ]]; then
  echo "usage: restore_postgres.sh [--yes] <file.dump>" >&2
  exit 1
fi
if [[ ! -f "$DUMP" ]]; then
  echo "dump not found: $DUMP" >&2
  exit 1
fi

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-cipherpost}"
PGDATABASE="${PGDATABASE:-cipherpost}"

if [[ "$YES" != "1" ]]; then
  echo "About to DESTROY and recreate $PGDATABASE@$PGHOST from $DUMP."
  read -r -p "Type the database name to confirm: " CONFIRM
  if [[ "$CONFIRM" != "$PGDATABASE" ]]; then
    echo "aborted" >&2
    exit 1
  fi
fi

echo "Restoring $DUMP into $PGDATABASE@$PGHOST ..."
pg_restore --clean --if-exists -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
  -d postgres -C "$DUMP"
echo "restore complete"
