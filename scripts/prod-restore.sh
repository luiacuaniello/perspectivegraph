#!/usr/bin/env bash
# Restore a dump the backup service wrote, in place of the database the engine runs on:
#
#   scripts/prod-restore.sh backups/pg-graph-<time>.dump     (make prod-restore DUMP=...)
#
# Run it where prod-init ran, beside .env. Everything the engine holds - the graph, triage,
# tickets, verdicts, the audit chain - becomes what the dump holds. The credentials do not
# change: they are ./secrets, and a dump restored under another STORE_ENCRYPTION_KEY has an
# audit chain that no longer opens.
#
# The dump goes into a new database first, and only once pg_restore has finished without an
# error does it take the old one's place - so a dump that turns out to be damaged costs a
# few minutes of downtime and nothing else. The backend and the backups are stopped for the
# duration, so nothing writes in between, and started again at the end.
#
# PG_RESTORE_YES=1 skips the confirmation (scripts/prod-smoke.sh, which runs this on every
# change: a restore never run is a hope, not a backup).
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "prod-restore: $*" >&2; exit 1; }
say() { echo "prod-restore: $*"; }

dump=${1:-}
if [ -z "$dump" ] || [ ! -f "$dump" ]; then
  die "usage: scripts/prod-restore.sh <dump> - the dumps are in ./backups"
fi
grep -qs '^COMPOSE_FILE=.*docker-compose\.vm\.yml' .env || die "no single-VM .env here: run this where prod-init ran"

# Read before anything stops: a file that is not an archive is refused while nothing is lost.
docker compose exec -T postgres pg_restore --list <"$dump" >/dev/null ||
  die "$dump is not an archive pg_restore can read; nothing was changed"

if [ "${PG_RESTORE_YES:-}" != 1 ]; then
  printf 'prod-restore: this replaces everything the engine holds with %s.\nType "restore" to go on: ' "$dump"
  read -r answer
  [ "$answer" = restore ] || die "nothing was changed"
fi

say "stopping the backend and the backups"
docker compose stop backend backup
# The dashboard is restarted too, so its nginx starts afresh against the restored backend
# (it resolves the backend's address once, at start). Docker gives a restarted container its
# address back, so this is a precaution: one early run of scripts/prod-smoke.sh, without it,
# saw the dashboard answer 502 after a restore, which no later run reproduced. It costs a
# second of the dashboard, during a window the backend is down anyway.
restart() {
  say "starting the backend and the backups"
  docker compose start backend backup
  docker compose restart frontend
}
trap restart EXIT

# A client tool in the database container, as the database's owner, over its local socket.
pg() { docker compose exec -T postgres sh -c 'tool=$1; shift; exec "$tool" -U "$POSTGRES_USER" "$@"' sh "$@"; }
db=$(docker compose exec -T postgres printenv POSTGRES_DB | tr -d '\r')
tmp="${db}_restore"

say "restoring into $tmp"
pg dropdb --if-exists "$tmp"
pg createdb "$tmp"
if ! pg pg_restore --no-owner --exit-on-error --dbname="$tmp" <"$dump"; then
  pg dropdb --if-exists "$tmp"
  die "pg_restore failed on $dump; the database was not touched"
fi

# Apache AGE names a graph in its own catalog by a raw OID - the OID of the graph's schema,
# in ag_graph.graphid and ag_label.graph. pg_dump writes those as plain numbers, and the
# schema a restore creates gets a new OID, so without this a restored database answers every
# query with "graph with oid N does not exist" (measured, AGE 1.7.0). Both are pointed back
# at the schema in one transaction; the foreign key between them does not cascade, so it is
# held off for that transaction (session_replication_role, which needs the superuser the
# bundled database's user is).
say "re-attaching the graph catalog to the restored schema"
if ! pg psql -q -v ON_ERROR_STOP=1 -d "$tmp" <<'SQL'
BEGIN;
SET LOCAL session_replication_role = replica;
UPDATE ag_catalog.ag_label l SET graph = g.namespace::oid
  FROM ag_catalog.ag_graph g
 WHERE l.graph = g.graphid AND g.graphid <> g.namespace::oid;
UPDATE ag_catalog.ag_graph SET graphid = namespace::oid WHERE graphid <> namespace::oid;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE graphid <> namespace::oid)
     OR EXISTS (SELECT 1 FROM ag_catalog.ag_label l
                 WHERE NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph g WHERE g.graphid = l.graph)) THEN
    RAISE EXCEPTION 'the graph catalog still names a schema that does not exist';
  END IF;
END $$;
COMMIT;
SQL
then
  pg dropdb --if-exists "$tmp"
  die "could not re-attach the graph catalog in the restored copy; the database was not touched"
fi

say "swapping it in for $db"
pg psql -q -v ON_ERROR_STOP=1 -d postgres \
  -c "DROP DATABASE \"$db\" WITH (FORCE)" \
  -c "ALTER DATABASE \"$tmp\" RENAME TO \"$db\""
say "restored $dump"
