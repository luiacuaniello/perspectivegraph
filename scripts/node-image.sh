#!/usr/bin/env bash
# Print the Node image the release build uses, read from frontend/Dockerfile - the one
# place Node is named.
#
#   scripts/node-image.sh             node:24.21.0-alpine@sha256:…   (make lockfile)
#   scripts/node-image.sh --version   24.21.0                         (CI's setup-node)
#
# Node used to be written out in four places: the Dockerfile, the Makefile's lockfile
# writer, and two `node-version` pins in ci.yml. Dependabot can only edit the first, so
# every rebuild of the Node image arrived as a partial update - PR #204 moved the
# Dockerfile to Node 24.21.0 while CI and the lockfile writer stayed on 24.20.0, and the
# parity test refused it. Everything else now asks the Dockerfile, which makes the
# bump Dependabot proposes a complete one.
set -euo pipefail

dockerfile="$(cd "$(dirname "$0")/.." && pwd)/frontend/Dockerfile"

# Exactly one match, or stop: a second Node stage, or a FROM line in a shape this does
# not recognise, must fail loudly rather than hand CI the wrong Node or none at all.
matches="$(sed -n 's/^FROM --platform=\$BUILDPLATFORM \(node:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-alpine@sha256:[0-9a-f]\{64\}\) AS build$/\1 \2/p' "$dockerfile")"
if [ "$(printf '%s\n' "$matches" | grep -c .)" != 1 ]; then
  echo "node-image: expected exactly one 'FROM --platform=\$BUILDPLATFORM node:X.Y.Z-alpine@sha256:<digest> AS build' in $dockerfile" >&2
  exit 1
fi

read -r image version <<<"$matches"
case "${1:-}" in
  "") echo "$image" ;;
  --version) echo "$version" ;;
  *) echo "usage: $0 [--version]" >&2; exit 2 ;;
esac
