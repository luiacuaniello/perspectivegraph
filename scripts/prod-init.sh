#!/usr/bin/env bash
# Production on one machine, in one command: `make prod-init DOMAIN=<name>`.
#
# Run it on the VM, from a checkout of a release tag, as a user in the docker group rather
# than as root: the backups are written as whoever runs it. It keeps whatever exists, so
# running it again after checking out a newer release is the upgrade (DOMAIN is then read
# back from .env).
#
#   1. secrets/  every credential, generated once and never replaced: a new database
#                password would lock the backend out of the data the old one protects.
#   2. backups/  where the backup service writes its dumps.
#   3. .env      the instance: its name, the compose files the stack is made of, and who
#                owns the backups. Written once; edit it afterwards (connectors, SSO).
#   4. docker compose up, then waits until the dashboard answers through Caddy.
#
# docs/manual/single-vm.md is the procedure around it: DNS and firewall first, then sources,
# backups off the machine, and the restore (scripts/prod-restore.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "prod-init: $*" >&2; exit 1; }
say() { echo "prod-init: $*"; }

domain=${1:-${DOMAIN:-}}
if [ -z "$domain" ] && [ -f .env ]; then
  domain=$(sed -n 's/^DOMAIN=//p' .env)
fi
[ -n "$domain" ] || die "usage: make prod-init DOMAIN=<the name this machine answers to>"
# A host name, not a URL: Caddy asks for a certificate for exactly this string.
case "$domain" in
  *[!A-Za-z0-9.-]* | .* | *. ) die "DOMAIN is a host name, like perspectivegraph.example.com - not '$domain'" ;;
esac

command -v docker >/dev/null || die "docker is not installed"
ver=$(docker compose version --short 2>/dev/null) || die "the Docker Compose plugin is not installed"
# The overlay withdraws ports with `!reset`, which Compose reads from 2.24 on; older ones
# fail on it with a YAML error that names neither.
v=${ver#v}; major=${v%%.*}; v=${v#*.}; minor=${v%%.*}
if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 24 ]; }; then
  die "Docker Compose $ver is too old for this recipe: it needs 2.24 or newer"
fi

# ── 1. Credentials ──────────────────────────────────────────────────────────────────────
# Readable by everyone (644) inside a directory only you can enter (700). The containers
# open the files as their own users - the backend as uid 65532, Postgres as 999 - and a bind
# mount keeps the host's owner and mode, so on Linux a 600 file of yours is one they cannot
# read (Docker Desktop hides this; a server does not). The directory keeps out every other
# user of this machine.
mkdir -p secrets backups
chmod 700 secrets backups

hex() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
secret() {
  local f="secrets/$1"
  if [ -s "$f" ]; then
    say "kept      $f"
  else
    printf '%s' "$2" >"$f"
    say "generated $f"
  fi
  chmod 644 "$f"
}
secret postgres_password "$(hex)"
secret ingest_hmac_secret "$(hex)"
secret api_tokens "$(hex):admin"
secret store_encryption_key "$(hex)"
secret export_signing_key "$(hex)"
secret nats_password "$(hex)"
# What nats-server reads, derived from nats_password every time so the two cannot disagree.
# The user is the NATS_USER docker-compose.vm.yml gives the backend.
printf 'authorization {\n  user: perspectivegraph\n  password: "%s"\n}\n' "$(cat secrets/nats_password)" >secrets/nats_auth.conf
chmod 644 secrets/nats_auth.conf

# ── 2. The instance ─────────────────────────────────────────────────────────────────────
if [ -f .env ]; then
  grep -q '^COMPOSE_FILE=.*docker-compose\.vm\.yml' .env ||
    die ".env exists and is not this recipe's - it configures another way of running the stack. Move it aside and run again."
  existing=$(sed -n 's/^DOMAIN=//p' .env)
  [ "$existing" = "$domain" ] ||
    die ".env serves $existing, not $domain. To change the name, edit DOMAIN in .env (Caddy then asks for a certificate for the new one)."
  say "kept      .env"
else
  (
    umask 077
    cat >.env <<EOF
# The single-VM production stack, written by scripts/prod-init.sh on $(date -u +%Y-%m-%d).
# docker compose reads this file, so its commands need no -f flags in this directory.
# The credentials are not here: they are the files in ./secrets.
COMPOSE_FILE=docker-compose.yml:docker-compose.demo.yml:docker-compose.secrets.yml:docker-compose.vm.yml
COMPOSE_PROFILES=app
DOMAIN=$domain
# The backup service writes ./backups as this user.
BACKUP_UID=$(id -u)
BACKUP_GID=$(id -g)

# Everything else the backend reads can be set below; docs/manual/configuration.md lists
# it all, and docker-compose.vm.yml's production defaults give way to it. For instance, on
# EC2, reading the account with the instance's own role:
#   CONNECTORS_ENABLED=aws
#   AWS_CONNECTOR_MODE=sdk
#   AWS_REGION=eu-west-1
EOF
  )
  say "wrote     .env"
fi

# ── 3. Start ────────────────────────────────────────────────────────────────────────────
# Caddy's image is the one built here; every other image is the release's, pulled. Not
# `up --build`: that rebuilds every service the base file can build - the backend, the
# dashboard, the database - from source, on this machine, and tags each build with the
# release's own name (ghcr.io/...:vX.Y.Z), so an unsigned local image then runs under the
# name of the signed one. Measured, on the first run of scripts/prod-smoke.sh.
say "building Caddy's image"
docker compose build caddy
say "starting: pulling the release's signed images"
docker compose up -d

# Asked of Caddy on this machine, by name, so it holds before DNS has propagated and where
# the cloud's network does not route a machine back to its own public address. -k because
# the first certificate may still be on its way: this checks the stack, the certificate is
# Caddy's to report (docker compose logs caddy).
if command -v curl >/dev/null; then
  say "waiting for https://$domain/ to answer"
  code=000
  for _ in $(seq 1 60); do
    code=$(curl -ks -o /dev/null -w '%{http_code}' --resolve "$domain:443:127.0.0.1" "https://$domain/" || true)
    [ "$code" = 200 ] && break
    sleep 3
  done
  [ "$code" = 200 ] || die "https://$domain/ did not answer within three minutes (last status $code).
  Check that $domain resolves to this machine and that ports 80 and 443 reach it, then:
    docker compose ps
    docker compose logs caddy"
fi

cat <<EOF

  PerspectiveGraph is up on https://$domain

  Sign in          the admin token is the part before ':' in secrets/api_tokens:
                     cut -d: -f1 secrets/api_tokens
  Send a report    signed with secrets/ingest_hmac_secret, e.g. with the release's CLI:
                     INGEST_HMAC_SECRET_FILE=secrets/ingest_hmac_secret \\
                       perspectivegraph ingest -url https://$domain trivy trivy.json
  Backups          a dump in ./backups every day. Copy them off this machine, and keep
                   ./secrets apart from them: together they are the whole attack map.
  Restore          scripts/prod-restore.sh backups/<dump>
  Status           docker compose ps

EOF
