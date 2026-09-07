#!/usr/bin/env bash
# Install the chart on a throwaway kind cluster and wait for every pod to be ready.
#
# This exists because `helm lint` and `helm template` cannot see the failure they were
# supposed to prevent. The chart set `runAsNonRoot: true` on the Postgres and NATS pods
# without a runAsUser, and every image it deployed left USER empty - so the kubelet
# refused both containers with "container has runAsNonRoot and image will run as root",
# the backend sat in Init:0/2 behind them forever, and `helm install` with the DEFAULT
# values could never have worked on any cluster. CI was green throughout: it rendered the
# templates and checked them against the restricted Pod Security Standard, which they
# passed, because the missing piece was in the images and not in the YAML.
#
# A render is not an install. This installs.
#
#   NODE_IMAGE=kindest/node:v1.33.12  bash scripts/chart-install.sh
#   KEEP=1                            leaves the cluster up for inspection
set -euo pipefail

CLUSTER="${CLUSTER:-perspectivegraph-chart}"
# Node images are coupled to the kind binary, not free to pick: kind v0.31 writes a
# kubeadm config in the v1beta3 API, and a v1.37 node refuses it outright ("your
# configuration file uses an old API spec"); a v1.36.4 node ships a containerd whose
# config version `kind load` cannot parse ("unknown containerd config version: 4").
# v1.36.1 is what this kind ships and boots. Bump kind before bumping this.
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
CHART="deploy/helm/perspectivegraph"
RELEASE="${RELEASE:-chartprobe}"
KEEP="${KEEP:-0}"

die() { echo "chart-install: $*" >&2; exit 1; }
ok()  { echo "chart-install: $*"; }

for tool in kind kubectl helm docker; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "chart-install: KEEP=1, leaving cluster '$CLUSTER' up (kind delete cluster --name $CLUSTER)"
    return
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
ok "creating cluster on ${NODE_IMAGE%%@*}"
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 180s >/dev/null

# The chart points at the published database image for the release it belongs to, which
# does not exist yet for the commit under test. Build it and hand it to the node.
ok "building the Postgres+AGE image"
docker build -q -t perspectivegraph-postgres:charttest deploy/postgres >/dev/null

# `kind load docker-image` would be the obvious call and it is avoided on purpose: on a
# host whose Docker keeps a containerd image store it dies with "unknown containerd config
# version: 4 (supported versions: 2 and 3)" before it copies anything, while the node's own
# containerd is quite happy on version 2. Piping the archive straight into the node's
# containerd skips kind's loader and behaves the same on a laptop and on a CI runner.
docker save perspectivegraph-postgres:charttest \
  | docker exec -i "${CLUSTER}-control-plane" ctr --namespace=k8s.io images import - >/dev/null \
  || die "could not import the database image into the node"

ok "helm install with default values"
if ! helm install "$RELEASE" "$CHART" \
      --kube-context "kind-$CLUSTER" \
      --set postgres.image.repository=perspectivegraph-postgres \
      --set postgres.image.tag=charttest \
      --wait --timeout 360s >/dev/null; then
  echo "--- pods ---"
  kubectl --context "kind-$CLUSTER" get pods
  echo "--- container states ---"
  kubectl --context "kind-$CLUSTER" get pods -o json \
    | python3 -c 'import json,sys
for p in json.load(sys.stdin)["items"]:
    for s in (p["status"].get("containerStatuses") or []) + (p["status"].get("initContainerStatuses") or []):
        print(p["metadata"]["name"], s["name"], json.dumps(s["state"]))'
  die "helm install failed"
fi

# --wait already gates on readiness; assert it separately so a chart that stops declaring
# probes cannot make this pass by having nothing to wait for.
not_ready=$(kubectl --context "kind-$CLUSTER" get pods \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' \
  | grep -v ' Running$' || true)
[ -z "$not_ready" ] || die "pods not Running:\n$not_ready"

# The database is the reason this image is built here at all: prove the extension is
# actually loadable, not merely that the container started.
ok "checking Apache AGE inside the cluster"
version=$(kubectl --context "kind-$CLUSTER" exec "${RELEASE}-perspectivegraph-postgres-0" -- \
  psql -U perspective -d perspectivegraph -tAc \
  "SELECT extversion FROM pg_extension WHERE extname='age'" 2>/dev/null | tr -d '[:space:]')
[ -n "$version" ] || die "the age extension is not installed in the bundled database"
ok "apache age $version loaded"

count=$(kubectl --context "kind-$CLUSTER" get pods --no-headers | wc -l | tr -d ' ')
ok "PASS - $count pod(s) running on ${NODE_IMAGE%%@*}"
