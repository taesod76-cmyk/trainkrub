#!/usr/bin/env bash
# TRAINKUB nightly backup.
# Reads five tables with the read-only login, checks them against the last good day, packs them and encrypts the pack with the
# PUBLIC certificate (only the private key kept by the owner can open it).
#
# Needs: psql, python3, openssl.
# Environment: PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGSSLMODE (the usual psql ones)
# Optional:    OUT (where the encrypted file goes)  STATE (yesterday's numbers)  CERT (public certificate)
#              ACCEPT=1 (take today's numbers as the new normal after a real, intended drop)
#              SIMULATE_ALARM=1 (pretend data went missing, to test that the alert email arrives)
# Exit code:   0 all good, 1 could not read or pack, 2 the data looks wrong (a backup is still made and kept)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-"$PWD/out"}
STATE=${STATE:-"$PWD/state"}
CERT=${CERT:-"$HERE/backup_cert.pem"}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%MZ)}
WORK="$OUT/work"

[ -f "$CERT" ] || { echo "no public certificate at $CERT"; exit 1; }
rm -rf "$WORK"; mkdir -p "$WORK" "$STATE"

# one snapshot of all five tables (a single read-only transaction, so they agree with each other)
cat > "$WORK/dump.sql" <<SQL
\set ON_ERROR_STOP on
\set FETCH_COUNT 500
\pset tuples_only on
\pset format unaligned
begin transaction isolation level repeatable read read only;
\o $WORK/public.kv_store.jsonl
select row_to_json(t) from public.kv_store t;
\o $WORK/app_private.cred.jsonl
select row_to_json(t) from app_private.cred t;
\o $WORK/app_private.push_config.jsonl
select row_to_json(t) from app_private.push_config t;
\o $WORK/app_private.push_subs.jsonl
select row_to_json(t) from app_private.push_subs t;
\o $WORK/app_private.audit.jsonl
select row_to_json(t) from app_private.audit t;
\o
commit;
SQL
if ! psql -X -q -v ON_ERROR_STOP=1 -f "$WORK/dump.sql" >/dev/null 2> "$WORK/dump.err"; then
  echo "could not read the database:"; sed -e 's/password=[^ ]*/password=***/' "$WORK/dump.err" | head -5
  rm -rf "$WORK"; exit 1
fi
rm -f "$WORK/dump.sql" "$WORK/dump.err"

# check the numbers against the last good day (writes manifest.json; exit 2 = something looks wrong)
CHECK=0
python3 "$HERE/backup_check.py" --work "$WORK" --state "$STATE" --stamp "$STAMP" \
  ${ACCEPT:+--accept} ${SIMULATE_ALARM:+--simulate-alarm} || CHECK=$?
[ "$CHECK" = 1 ] && { rm -rf "$WORK"; exit 1; }

# pack, then lock with the public certificate; the plain files never leave this machine
mkdir -p "$OUT"
( cd "$WORK" && tar -czf "$OUT/pack.tar.gz" manifest.json *.jsonl )
FILE="$OUT/trainkub-backup-$STAMP.tar.gz.cms"
openssl cms -encrypt -binary -aes-256-cbc -stream -outform DER -in "$OUT/pack.tar.gz" -out "$FILE" "$CERT"
rm -rf "$WORK" "$OUT/pack.tar.gz"
[ -s "$FILE" ] || { echo "the encrypted file is empty"; exit 1; }
echo "backup written: $(basename "$FILE") ($(wc -c < "$FILE") bytes)"
exit "$CHECK"
