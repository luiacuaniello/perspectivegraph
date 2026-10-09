#!/usr/bin/env bash
# Pull Docker Hub's images through Google's mirror on a CI runner: for the job's Docker
# daemon here, and for kind's nodes through REGISTRY_MIRROR, which scripts/chart-install.sh
# reads.
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

# The runner's daemon already has a configuration of its own; add to it, do not replace it.
current='{}'
if sudo test -s "$conf"; then current=$(sudo cat "$conf"); fi
echo "$current" | jq --arg m "$MIRROR" '."registry-mirrors" = [$m]' | sudo tee "$conf" >/dev/null
sudo systemctl restart docker
docker info --format '{{.RegistryConfig.Mirrors}}' | grep -q "${MIRROR#https://}" ||
  { echo "ci-docker-mirror: the daemon did not take the mirror" >&2; exit 1; }

echo "REGISTRY_MIRROR=$MIRROR" >>"$GITHUB_ENV"
echo "ci-docker-mirror: Docker Hub pulls go through $MIRROR"
