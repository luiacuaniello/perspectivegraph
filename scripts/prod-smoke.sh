#!/usr/bin/env bash
# Run the single-VM recipe end to end, the way an operator would, and check what it promises:
#
#   bash scripts/prod-smoke.sh        (make prod-smoke)
#   KEEP=1                            leave the stack and its directory up for inspection
#   PG_CLI=<path>                     a Linux build of the CLI, instead of building one with Go
#
# It copies this working tree to a scratch directory - prod-init writes .env, ./secrets and
# ./backups, none of which belongs in a checkout - and runs scripts/prod-init.sh there with
# DOMAIN=localhost, for which Caddy issues a certificate from a CA of its own. Then:
#
#   * only Caddy publishes a port;
#   * the dashboard answers over TLS that verifies against Caddy's CA, with HSTS;
#   * the API refuses a request without the generated admin token and accepts one with it;
#   * NATS refuses a client without the password;
#   * an unsigned report is refused at https://localhost/ingest/, and one signed with the
#     generated secret is applied, through Caddy, by the release's CLI;
#   * the backup service writes a dump as the operator, mode 600;
#   * a restore of that dump brings back the graph as it was when the dump was taken, after
#     more was ingested;
#   * running prod-init again changes no credential.
#
# Linux is where it matters: a bind mount keeps the host's owners and modes, which Docker
# Desktop papers over, so CI runs this on Linux.
set -euo pipefail

die() { echo "prod-smoke: FAIL: $*" >&2; exit 1; }
ok()  { echo "prod-smoke: $*"; }

repo=$(cd "$(dirname "$0")/.." && pwd)
KEEP="${KEEP:-0}"

if docker ps -a --format '{{.Names}}' | grep -q '^perspective-'; then
  die "containers named perspective-* exist (docker ps -a); the recipe uses those names - stop that stack first"
fi

W="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$W/.smoke"
cleanup() {
  status=$?
  if [ "$KEEP" = 1 ]; then
    ok "kept: cd $W && docker compose ps"
  else
    (cd "$W" && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
    rm -rf "$W"
  fi
  exit "$status"
}
trap cleanup EXIT

# The working tree as it is - committed or not, minus what git ignores (.env, secrets/).
ok "copying the working tree to $W"
(cd "$repo" && git ls-files -co --exclude-standard | while IFS= read -r f; do
  [ -e "$f" ] && printf '%s\0' "$f"
done | tar --null -T - -cf -) | tar -xf - -C "$W"

arch=$(docker version --format '{{.Server.Arch}}')
if [ -z "${PG_CLI:-}" ]; then
  ok "building the CLI for linux/$arch"
  (cd "$repo/backend" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$W/.smoke/pg" ./cmd/perspectivegraph)
else
  cp "$PG_CLI" "$W/.smoke/pg"
fi

cd "$W"
bash scripts/prod-init.sh localhost
TOKEN=$(cut -d: -f1 secrets/api_tokens)

# ── Exposure ────────────────────────────────────────────────────────────────────────────
published=$(docker ps --filter name=perspective- --format '{{.Names}} {{.Ports}}' | grep -e '->' | cut -d' ' -f1 | sort)
[ "$published" = perspective-caddy ] || die "want only perspective-caddy publishing ports, got: $(echo "$published" | tr '\n' ' ')"
ok "only Caddy publishes a port"

# ── TLS ─────────────────────────────────────────────────────────────────────────────────
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .smoke/ca.crt >/dev/null
CA=.smoke/ca.crt
headers=$(curl -fsS --cacert "$CA" -D - -o /dev/null https://localhost/) || die "the dashboard does not answer over verified TLS"
echo "$headers" | grep -qi '^strict-transport-security: max-age=' || die "no HSTS header"
echo "$headers" | grep -qi '^server:' && die "the Server header is still sent"
ok "the dashboard answers over TLS verified against Caddy's CA, with HSTS"

# ── API authentication ──────────────────────────────────────────────────────────────────
gql() {
  curl -sS --cacert "$CA" -H 'Content-Type: application/json' "$@" \
    -d '{"query":"{ graph { nodes { id } } }"}' -o .smoke/gql.json -w '%{http_code}' https://localhost/graphql
}
code=$(gql)
[ "$code" = 401 ] || die "the API answered $code without a token, want 401"
code=$(gql -H "Authorization: Bearer $TOKEN")
[ "$code" = 200 ] || die "the API answered $code with the admin token, want 200"
role=$(curl -fsS --cacert "$CA" -H "Authorization: Bearer $TOKEN" https://localhost/auth/me)
case "$role" in *'"admin"'*) ;; *) die "/auth/me with the admin token: $role" ;; esac
ok "the API refuses a request without the generated token and accepts the token as admin"

# ── NATS ────────────────────────────────────────────────────────────────────────────────
net=$(docker inspect perspective-nats --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')
nats=$(docker run --rm --network "$net" busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028 \
  sh -c 'printf "CONNECT {\"verbose\":false}\r\nPING\r\n" | nc -w 3 nats 4222' || true)
case "$nats" in *'Authorization Violation'*) ;; *) die "NATS accepted a client without credentials: $nats" ;; esac
ok "NATS refuses a client without the password"

# ── Ingest through Caddy ────────────────────────────────────────────────────────────────
code=$(curl -sS --cacert "$CA" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data-binary @backend/testdata/trivy-sample.json https://localhost/ingest/trivy)
[ "$code" = 401 ] || die "an unsigned report got $code at https://localhost/ingest/trivy, want 401"

# The CLI runs in Caddy's network namespace, where "localhost" is Caddy and the name on its
# certificate, and verifies against Caddy's CA - the same request a CI job makes.
ingest() {
  docker run --rm --network container:perspective-caddy \
    -v "$W/.smoke/pg:/pg:ro" -v "$W/$CA:/ca.crt:ro" -v "$W/secrets/ingest_hmac_secret:/hmac:ro" \
    -v "$W/backend/testdata/$2:/report.json:ro" \
    -e SSL_CERT_FILE=/ca.crt -e INGEST_HMAC_SECRET_FILE=/hmac -e API_TOKEN="$TOKEN" \
    busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028 \
    /pg ingest -url https://localhost -api https://localhost -wait "$1" /report.json
}
nodes() { gql -H "Authorization: Bearer $TOKEN" >/dev/null; grep -o '"id"' .smoke/gql.json | wc -l | tr -d ' '; }

ingest trivy trivy-sample.json || die "a signed report was not applied through Caddy"
before=$(nodes)
[ "$before" -gt 0 ] || die "the graph is empty after a signed report was applied"
ok "an unsigned report is refused at /ingest/; a signed one is applied through Caddy ($before nodes)"

# ── Backup ──────────────────────────────────────────────────────────────────────────────
docker compose run --rm backup once >/dev/null || die "the backup service could not write a dump"
dump=$(find backups -name 'pg-graph-*.dump' | sort | tail -1)   # the names sort by time
mode=$(stat -c '%a %u' "$dump" 2>/dev/null || stat -f '%Lp %u' "$dump")
[ "$mode" = "600 $(id -u)" ] || die "$dump is '$mode' (mode owner), want '600 $(id -u)'"
docker compose exec -T backup sh /usr/local/bin/pg-backup.sh check || die "the backup healthcheck fails with a fresh dump"
ok "the backup service wrote $dump, 600 and owned by the operator"

# ── Restore ─────────────────────────────────────────────────────────────────────────────
ingest custodian custodian-sample.json || die "the second report was not applied"
after=$(nodes)
[ "$after" -gt "$before" ] || die "the second report added nothing ($before -> $after nodes); the restore would prove nothing"
PG_RESTORE_YES=1 bash scripts/prod-restore.sh "$dump"
restored=
for _ in $(seq 1 40); do
  restored=$(nodes 2>/dev/null || true)
  [ "$restored" = "$before" ] && break
  sleep 3
done
[ "$restored" = "$before" ] || die "after the restore the graph has $restored nodes, want $before (the dump's)"
ok "the restore brought back the graph as dumped: $after -> $restored nodes"

# ── Idempotence ─────────────────────────────────────────────────────────────────────────
sum=$(cat secrets/* | cksum)
bash scripts/prod-init.sh >/dev/null
[ "$(cat secrets/* | cksum)" = "$sum" ] || die "running prod-init again changed a credential"
ok "running prod-init again kept every credential"

ok "PASS"
