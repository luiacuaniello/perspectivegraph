#!/usr/bin/env bash
# Pull Docker Hub's images through Google's mirror on a CI runner: for the job's Docker
# daemon here, and for kind's nodes through REGISTRY_MIRROR, which scripts/chart-install.sh
# reads.
#
#   ci-docker-mirror.sh [file...]
#
# Given files, it also pulls the Docker Hub images they pin by digest, now and with retries,
# so the job's own builds and `compose up` find them present: every FROM of a Dockerfile, and
# the images of a compose file's services in the default and app profiles - not those of the
# optional ones (OpenSearch, Keycloak), which no job starts.
#
# Docker Hub limits anonymous pulls per address, and a hosted runner shares its address with
# other people's jobs. On 2026-10-09 five jobs of a documentation-only pull request failed in
# their first minute on "429 Too Many Requests", pulling the node, postgres and golang images
# - nothing to do with the change under review.
#
# mirror.gcr.io serves Docker Hub's images, and every image this repository takes from Docker
# Hub is pinned by digest, so which registry answers cannot change what arrives: a different
# byte is a different digest, and the pull fails. A digest the mirror does not hold is still
# fetched from Docker Hub. Checked with Docker Hub made unreachable: `docker build`, `docker
# pull` and a kind node's containerd all pulled the pinned images through the mirror.
set -euo pipefail

MIRROR=https://mirror.gcr.io
conf=/etc/docker/daemon.json

# The runner signs in to Docker Hub (as "githubactions"), and with credentials for docker.io
# the daemon does not use a mirror at all: every pull went straight to Docker Hub and met the
# 429, mirror configured or not. Measured on Docker 28.0.4, the runner's, with Docker Hub
# unreachable: the same pull succeeds through the mirror without them and fails with them.
# These jobs read public images and push nothing, so they need no credentials: drop Docker
# Hub's from the client's configuration, and keep the rest of it (its plugins, other hosts).
client="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
if [ -s "$client" ]; then
  jq '(.auths // {}) as $a
      | .auths = ($a | with_entries(select(.key | test("docker\\.io") | not)))
      | if .credHelpers then .credHelpers |= with_entries(select(.key | test("docker\\.io") | not)) else . end
      | del(.credsStore)' "$client" >"$client.new"
  mv "$client.new" "$client"
  echo "ci-docker-mirror: Docker Hub credentials dropped from $client"
fi

# The runner's daemon already has a configuration of its own; add to it, do not replace it.
current='{}'
if sudo test -s "$conf"; then current=$(sudo cat "$conf"); fi
echo "$current" | jq --arg m "$MIRROR" '."registry-mirrors" = [$m]' | sudo tee "$conf" >/dev/null
sudo systemctl restart docker
docker info --format '{{.RegistryConfig.Mirrors}}' | grep -q "${MIRROR#https://}" ||
  { echo "ci-docker-mirror: the daemon did not take the mirror" >&2; exit 1; }

echo "REGISTRY_MIRROR=$MIRROR" >>"$GITHUB_ENV"
echo "ci-docker-mirror: Docker Hub pulls go through $MIRROR"

# The daemon falls back to Docker Hub when the mirror fails a request, and a transient
# failure then meets the rate limit: measured, once, on busybox in `compose up`, in a run
# where every other pull went through the mirror. A pull retried after a pause goes to the
# mirror again.
pull() {
  local i
  for i in 1 2 3 4; do
    docker pull -q "$1" >/dev/null && { echo "ci-docker-mirror: pulled $1"; return 0; }
    echo "ci-docker-mirror: pulling $1 failed (attempt $i), retrying" >&2
    sleep $((i * 15))
  done
  return 1
}
refs() {
  local f
  for f in "$@"; do
    case "$f" in
      *.yml | *.yaml) docker compose -f "$f" --profile app config --images ;;
      *) grep -hE '^FROM ' "$f" ;;
    esac
  done | grep -oE '[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' | sort -u
}
[ "$#" -gt 0 ] || exit 0
# References with no registry host are Docker Hub's: nats:…@sha256:…, kindest/node:…@sha256:….
refs "$@" |
  while read -r ref; do
    case "$ref" in */*) case "${ref%%/*}" in *.* | *:*) continue ;; esac ;; esac
    pull "$ref"
  done
