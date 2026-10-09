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
#   DATABASE=cloudnativepg            the database run by the CloudNativePG operator
#   KEEP=1                            leaves the cluster up for inspection
#
# DATABASE=cloudnativepg installs the operator, lets it run a primary and a replica, and
# then does the one thing a production database is for: it deletes the primary and checks
# that a write still reaches the graph, through the replica the operator promoted.
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
DATABASE="${DATABASE:-bundled}"
# The operator, pinned to a release and to the bytes of its manifest: a checksum, not just
# a version, because the manifest is cluster-admin YAML fetched from a release CDN.
CNPG_VERSION=1.30.1
CNPG_SHA256=37237f145d8138256ea25ae830f87759255665ff08f8d552fdd8224a5ec032fb

case "$DATABASE" in
  bundled|cloudnativepg) ;;
  *) echo "chart-install: DATABASE must be bundled or cloudnativepg, not '$DATABASE'" >&2; exit 2 ;;
esac
# One database image either way: the operator runs the same one the chart bundles.
PG_IMAGE=perspectivegraph-postgres
PG_CONTEXT=deploy/postgres

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
# ALL THREE images are built here, not just the database, and that is not thoroughness -
# it is the only thing that works. The chart points every image at its own appVersion, and
# on a release branch appVersion is the version BEING released: `perspectivegraph:v1.12.7`
# does not exist while the release PR is open, because publish-images runs after it merges.
# Pulling would sit in ImagePullBackOff until the timeout. Building instead also tests the
# chart against the code under review rather than against the last release.
ok "building the three images the chart deploys"
docker build -q -t "${PG_IMAGE}:charttest" "$PG_CONTEXT" >/dev/null
docker build -q -t perspectivegraph-backend:charttest backend >/dev/null
docker build -q -t perspectivegraph-dashboard:charttest frontend >/dev/null

# `kind load docker-image` would be the obvious call and it is avoided on purpose: on a
# host whose Docker keeps a containerd image store it dies with "unknown containerd config
# version: 4 (supported versions: 2 and 3)" before it copies anything, while the node's own
# containerd is quite happy on version 2. Piping the archive straight into the node's
# containerd skips kind's loader and behaves the same on a laptop and on a CI runner.
for img in "$PG_IMAGE" perspectivegraph-backend perspectivegraph-dashboard; do
  docker save "${img}:charttest" \
    | docker exec -i "${CLUSTER}-control-plane" ctr --namespace=k8s.io images import - >/dev/null \
    || die "could not import ${img} into the node"
done

kc() { kubectl --context "kind-$CLUSTER" "$@"; }
probe_image=$(helm show values "$CHART" | awk '/^  waitImage:/ {print $2; exit}')

if [ "$DATABASE" = "cloudnativepg" ]; then
  ok "installing the CloudNativePG operator ${CNPG_VERSION}"
  manifest="$(mktemp)"
  curl -fsSL --retry 4 --retry-all-errors --retry-delay 3 --connect-timeout 20 -o "$manifest" \
    "https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v${CNPG_VERSION}/cnpg-${CNPG_VERSION}.yaml" \
    || die "could not download the operator manifest"
  echo "${CNPG_SHA256}  ${manifest}" | shasum -a 256 -c - >/dev/null \
    || die "the operator manifest does not match its pinned checksum"
  kc apply --server-side -f "$manifest" >/dev/null
  kc -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=180s >/dev/null \
    || die "the operator did not become ready"
  # Ready is not the same as admitting: the operator validates every Cluster through a
  # webhook, which answers a moment after the pod does. Ask it, rather than sleep.
  admitted=0
  for _ in $(seq 1 30); do
    if printf '%s\n' 'apiVersion: postgresql.cnpg.io/v1' 'kind: Cluster' 'metadata: {name: webhook-probe}' \
         'spec: {instances: 1, storage: {size: 1Gi}}' | kc apply --dry-run=server -f - >/dev/null 2>&1; then
      admitted=1; break
    fi
    sleep 2
  done
  [ "$admitted" = 1 ] || die "the operator's webhook never answered"
  # graphStrict: the backend refuses to start without Apache AGE instead of falling back to
  # an in-memory graph - so its readiness below means the database works, not just that a
  # process is up.
  DB_ARGS=(--set postgres.cloudnativepg.enabled=true
           --set postgres.image.repository="$PG_IMAGE"
           --set postgres.image.tag=charttest
           --set postgres.cloudnativepg.storage.size=1Gi
           --set backend.graphStrict=true)
else
  DB_ARGS=(--set postgres.image.repository="$PG_IMAGE"
           --set postgres.image.tag=charttest)
fi

ok "helm install with default values (database: $DATABASE)"
if ! helm install "$RELEASE" "$CHART" \
      --kube-context "kind-$CLUSTER" \
      "${DB_ARGS[@]}" \
      --set backend.image.repository=perspectivegraph-backend \
      --set backend.image.tag=charttest \
      --set frontend.image.repository=perspectivegraph-dashboard \
      --set frontend.image.tag=charttest \
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
if [ "$DATABASE" = "bundled" ]; then
  version=$(kc exec "${RELEASE}-perspectivegraph-postgres-0" -- \
    psql -U perspective -d perspectivegraph -tAc \
    "SELECT extversion FROM pg_extension WHERE extname='age'" 2>/dev/null | tr -d '[:space:]')
  [ -n "$version" ] || die "the age extension is not installed in the bundled database"
  ok "apache age $version loaded"
else
  CL="${RELEASE}-perspectivegraph-pg"
  kc wait --for=condition=Ready "cluster/$CL" --timeout=300s >/dev/null || die "cluster $CL never became ready"
  ready=$(kc get cluster "$CL" -o jsonpath='{.status.readyInstances}')
  [ "$ready" = 2 ] || die "cluster $CL has $ready ready instance(s), not 2"
  primary=$(kc get cluster "$CL" -o jsonpath='{.status.currentPrimary}')
  # The superuser over the pod's local socket: the operator keeps it off the network. -q
  # keeps psql from printing a command tag for each statement before the result, which the
  # whitespace stripping would otherwise glue onto it ("LOADSET1" is not a count).
  sql() { kc exec "$1" -c postgres -- psql -q -U postgres -d perspectivegraph -tAc "$2" 2>/dev/null | tr -d '[:space:]'; }

  version=$(sql "$primary" "SELECT extversion FROM pg_extension WHERE extname='age'")
  [ -n "$version" ] || die "the age extension is not installed on the primary"
  ok "apache age $version loaded on $primary, with a replica beside it"

  # verify-full is the chart's default here, so a session that exists at all was checked
  # against the operator's CA and the Service's name. Check that it is encrypted too, from
  # the server's side - and that the graph's schema is the backend's, which it must create
  # itself to be able to write to.
  tls=""
  for _ in $(seq 1 30); do
    tls=$(sql "$primary" "SELECT bool_and(s.ssl) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename = 'perspective'")
    [ -n "$tls" ] && break
    sleep 2
  done
  [ "$tls" = t ] || die "the backend's sessions are not all encrypted (ssl: '${tls:-no session}')"
  owner=$(sql "$primary" "SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'perspective'")
  [ "$owner" = perspective ] || die "the graph schema is owned by '${owner:-nobody}', not by the backend's role"
  ok "the backend connects over verified TLS as a role that is not a superuser, and owns its graph"

  restarts_before=$(kc get pods -l app.kubernetes.io/component=backend -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
  # Killed, not deleted. A graceful delete is maintenance: the instance manager runs a
  # smart shutdown that waits up to three minutes for clients to disconnect - and the
  # backend's pool never does - before it lets go. A primary whose node dies gets no such
  # grace, and that is the case a replica exists for. Measured on kind: the replica was
  # promoted 21s after the kill, and the next write landed 4s later.
  ok "failing over: killing the primary, $primary"
  kc delete pod "$primary" --grace-period=0 --force >/dev/null 2>&1
  promoted="$primary"
  for _ in $(seq 1 90); do
    promoted=$(kc get cluster "$CL" -o jsonpath='{.status.currentPrimary}')
    [ -n "$promoted" ] && [ "$promoted" != "$primary" ] && break
    sleep 3
  done
  [ "$promoted" != "$primary" ] || die "no replica was promoted"
  role=$(kc get pod "$promoted" -o jsonpath='{.metadata.labels.cnpg\.io/instanceRole}')
  [ "$role" = primary ] || die "$promoted was named primary but its pod says '$role'"
  ok "$promoted promoted"

  # A write after the failover must land on the new primary: the backend reaches the
  # database through the -rw Service, which the operator moved, and reconnects on its own.
  payload='{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"failover-probe","namespace":"probe"}}]}'
  written=0
  for _ in $(seq 1 30); do
    kc run "ingestprobe-$RANDOM" --rm -i --restart=Never --quiet --image="$probe_image" --command -- \
      wget -q -O /dev/null --header 'Content-Type: application/json' --post-data "$payload" \
      "http://${RELEASE}-perspectivegraph-backend:8081/ingest/k8s?cluster=failover" >/dev/null 2>&1 || true
    n=$(sql "$promoted" "LOAD 'age'; SET search_path = ag_catalog, public; SELECT count(*) FROM cypher('perspective', \$\$MATCH (n) WHERE n.name = 'probe/failover-probe' RETURN n\$\$) AS (n agtype)")
    if [ "${n:-0}" -gt 0 ]; then written=1; break; fi
    sleep 4
  done
  [ "$written" = 1 ] || die "nothing written after the failover reached the new primary"
  restarts_after=$(kc get pods -l app.kubernetes.io/component=backend -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
  [ "$restarts_after" = "$restarts_before" ] || die "the backend restarted during the failover ($restarts_before -> $restarts_after)"
  ok "a write after the failover reached $promoted, and the backend did not restart"
fi

# The bus must refuse a client without credentials: events on it are trusted, and the
# ingest webhook's signature check runs before them, not after. The backend reaching it at
# all (--wait above) proves the password works; this proves it is required.
ok "checking that NATS refuses an unauthenticated client"
reply=$(kubectl --context "kind-$CLUSTER" run natsprobe --rm -i --restart=Never --quiet \
  --image="$probe_image" --command -- sh -c \
  "printf 'CONNECT {\"verbose\":true}\r\nPING\r\n' | nc -w 5 ${RELEASE}-perspectivegraph-nats 4222" 2>&1 || true)
case "$reply" in
  *"Authorization Violation"*) ok "nats refused it" ;;
  *) die "nats did not refuse an unauthenticated client:\n$reply" ;;
esac

count=$(kubectl --context "kind-$CLUSTER" get pods --no-headers | wc -l | tr -d ' ')
ok "PASS - $count pod(s) running on ${NODE_IMAGE%%@*}"
