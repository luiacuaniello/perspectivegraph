#!/bin/sh
# The backup service of the single-VM recipe (docker-compose.vm.yml): dumps the graph
# database into /backups (./backups on the host) every BACKUP_HOURS (24), keeping the newest
# BACKUP_KEEP (14).
#
#   (no argument)  the service: a dump now, then one every BACKUP_HOURS
#   once           one dump, then exit:  docker compose run --rm backup once
#   check          the healthcheck: is there a dump younger than BACKUP_HOURS + 1h?
#
# A dump is pg_dump's custom format: compressed, and what scripts/prod-restore.sh reads.
# It holds the whole engine - the graph, triage decisions, tickets, verdicts and the audit
# chain, because the recipe keeps all of them in Postgres - so it is as sensitive as the
# attack map itself: written 600, and to be copied off this machine encrypted.
set -eu
umask 077

hours=${BACKUP_HOURS:-24}
keep=${BACKUP_KEEP:-14}
case "$hours$keep" in
	*[!0-9]*) echo "backup: BACKUP_HOURS and BACKUP_KEEP must be whole numbers" >&2; exit 2 ;;
esac
# Zero hours is a loop that dumps without pause; zero kept deletes the dump just written.
if [ "$hours" -lt 1 ] || [ "$keep" -lt 1 ]; then
	echo "backup: BACKUP_HOURS and BACKUP_KEEP must be at least 1" >&2
	exit 2
fi

if [ "${1:-}" = check ]; then
	[ -n "$(find /backups -maxdepth 1 -name 'pg-graph-*.dump' -mmin -$((hours * 60 + 60)))" ]
	exit
fi

PGPASSWORD=$(cat /run/secrets/postgres_password)
export PGPASSWORD

dump() {
	name="pg-graph-$(date -u +%Y%m%dT%H%M%SZ).dump"
	# Written under another name and renamed once pg_dump succeeds, so a dump cut short - a
	# full disk, a restart - never sits in the directory looking like a finished one.
	if pg_dump --format=custom --no-owner --file="/backups/.$name.partial"; then
		mv "/backups/.$name.partial" "/backups/$name"
		echo "backup: wrote $name ($(wc -c <"/backups/$name") bytes)"
	else
		rm -f "/backups/.$name.partial"
		echo "backup: pg_dump failed; the earlier dumps are kept" >&2
		return 1
	fi
	# The names sort by time; everything past the newest $keep goes.
	find /backups -maxdepth 1 -name 'pg-graph-*.dump' | sort -r | tail -n +$((keep + 1)) |
		while read -r old; do
			rm -f "$old" && echo "backup: removed ${old#/backups/}"
		done
}

if [ "${1:-}" = once ]; then
	dump
	exit
fi
while :; do
	dump || true
	sleep $((hours * 3600))
done
