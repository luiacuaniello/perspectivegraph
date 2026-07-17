#!/usr/bin/env bash
#
# validate-harness-aws.sh - real-topology calibration on a live AWS account, using a
# CloudGoat scenario as INDEPENDENT ground truth (its attack paths were designed by
# someone else, so confirming/refuting one is not circular).
#
# The engine only seeds paths from internet exposure, but CloudGoat models an attacker who
# already holds leaked credentials - so to make the network-connected path surface, this
# briefly opens the scenario instance's security group to 0.0.0.0/0, lets the read-only
# connector snapshot the topology (seconds), and IMMEDIATELY closes it again. The box is
# therefore world-exposed only for the snapshot; the verdict's exploit uses the scenario's
# own API credentials, not the network. An EXIT trap re-closes the window even if this
# script dies.
#
#   YOU manage the CloudGoat lifecycle (cost + risk stay in your hands):
#     cd ~/labs/cloudgoat && cloudgoat create iam_privesc_by_attachment
#     CONFIRM=i-understand-internet-exposure REGION=us-east-1 \
#       ROLE_ARN=arn:aws:iam::<acct>:role/PerspectiveGraphReadOnly \
#       make validate-harness-aws
#     # ...run the scenario's documented exploit, then re-run with OUTCOME=confirmed|refuted
#     cloudgoat destroy iam_privesc_by_attachment
#
# Requires: aws CLI (a profile with EC2 authorize/revoke rights, e.g. AWS_PROFILE=pg-admin),
# the stack up (make up-full), jq, and a deployed CloudGoat scenario.
#
# HONEST NOTE: this harness was NOT run end-to-end by its author (no AWS in that sandbox).
# It automates the safe glue - open/snapshot/close, ingest, score, record - and leaves the
# exploit to you. Expect to debug it on first contact; that is the point of M1.
set -euo pipefail

REGION=${REGION:-${AWS_REGION:-}}
ROLE_ARN=${ROLE_ARN:-}
API_URL=${API_URL:-http://localhost:8080}
INGEST_URL=${INGEST_URL:-http://localhost:8081}
SG_ID=${SG_ID:-}
OUTCOME=${OUTCOME:-}                       # confirmed|refuted → record a verdict for the found path
ANALYZER_WAIT=${ANALYZER_WAIT:-35}
GO=${GO:-go}; export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.12}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m  %s\n' "$*"; }
die()  { printf '  \033[31mx\033[0m  %s\n' "$*" >&2; exit 1; }

# ── Preconditions ────────────────────────────────────────────────────
for b in aws jq curl "$GO"; do command -v "$b" >/dev/null 2>&1 || die "$b not found"; done
[ -n "$REGION" ]   || die "set REGION (or AWS_REGION) to the scenario's region"
[ -n "$ROLE_ARN" ] || die "set ROLE_ARN to your read-only role (the connector assumes it)"
curl -sf "$API_URL/healthz" >/dev/null 2>&1 || die "stack unreachable at $API_URL (run: make up-full)"
[ "${CONFIRM:-}" = "i-understand-internet-exposure" ] || die \
  "this briefly exposes a deliberately-vulnerable EC2 to 0.0.0.0/0. Re-run with CONFIRM=i-understand-internet-exposure once you accept that."

# ── Find the scenario's security group (or take SG_ID) ───────────────
say "1. locate the CloudGoat instance + its security group in $REGION"
if [ -z "$SG_ID" ]; then
  SG_ID=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Name,Values=cg-*" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].SecurityGroups[].GroupId' --output text 2>/dev/null | tr '\t' '\n' | sort -u | head -1)
fi
[ -n "$SG_ID" ] || die "no cg-* instance/SG found in $REGION (deploy a scenario first, or pass SG_ID=sg-...)"
ok "security group: $SG_ID"

# ── Open the window, snapshot, and ALWAYS close it (trap) ────────────
WINDOW_OPEN=""
close_window() {
  [ -n "$WINDOW_OPEN" ] || return 0
  aws ec2 revoke-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
  warn "internet window CLOSED (revoked 0.0.0.0/0 on $SG_ID:22)"
  WINDOW_OPEN=""
}
cleanup() { close_window; rm -rf "$TMP"; }
trap cleanup EXIT

say "2. open a brief internet window so the engine sees the instance as a seed"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 && WINDOW_OPEN=1 \
  || warn "authorize returned non-zero (rule may already exist) - continuing"
ok "internet window OPEN on $SG_ID:22 (will close right after the snapshot)"

say "3. read the REAL topology (read-only) and push it into the stack"
$GO build -o "$TMP/pg" "$ROOT/backend/cmd/perspectivegraph" 2>/dev/null \
  || (cd "$ROOT/backend" && $GO build -o "$TMP/pg" ./cmd/perspectivegraph) || die "CLI build failed"
"$TMP/pg" awscollect -region "$REGION" -role "$ROLE_ARN" -ingest "$INGEST_URL" || die "awscollect failed"
close_window   # exposure ends here - the snapshot is in; the box is private again

# ── Score: did a complete internet → sensitive-asset path form? ──────
say "4. wait for the analyzer, then look for a scored path from the scenario"
sleep "$ANALYZER_WAIT"
PATHS=$(curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ attackPaths(limit:50){ id score priority nodes { name } } }"}' \
  | jq -c '[.data.attackPaths[] | select(.nodes[0].name | test("^cg-|internet|edge-|lb"; "i")) | {id, score, priority, route: ([.nodes[].name] | join(" -> "))}]')
n=$(printf '%s' "$PATHS" | jq 'length')
if [ "${n:-0}" -eq 0 ]; then
  warn "no internet-seeded path from the scenario formed."
  warn "This is itself a real finding: CloudGoat models a leaked-credential attacker, so the"
  warn "engine's internet-origin threat model may not reach the scenario's goal. Inspect the"
  warn "raw graph:  (cd backend && go run ./cmd/perspectivegraph awscollect -region $REGION -role $ROLE_ARN -json) | jq ."
  exit 0
fi
ok "$n path(s) surfaced:"
printf '%s' "$PATHS" | jq -r '.[] | "    [\(.priority)] score=\(.score)  \(.route)"'
TOP_ID=$(printf '%s' "$PATHS" | jq -r 'sort_by(-.priority)[0].id')
TOP_SCORE=$(printf '%s' "$PATHS" | jq -r 'sort_by(-.priority)[0].score')

# ── Verdict: record the outcome of the (operator-run) exploit ────────
say "5. verdict"
if [ -z "$OUTCOME" ]; then
  cat <<EOF
  The engine surfaced path $TOP_ID (score $TOP_SCORE). To calibrate, run the scenario's
  DOCUMENTED exploit (see its cheat_sheet in ~/labs/cloudgoat/<scenario>_*/), decide whether
  the escalation genuinely succeeds, then re-run this with the outcome:

      OUTCOME=confirmed  CONFIRM=i-understand-internet-exposure REGION=$REGION \\
        ROLE_ARN=$ROLE_ARN make validate-harness-aws
      # ...or OUTCOME=refuted if the escalation was blocked.
EOF
  exit 0
fi
case "$OUTCOME" in confirmed|refuted) ;; *) die "OUTCOME must be 'confirmed' or 'refuted'";; esac
printf '{"source":"cloudgoat-harness","findings":[{"pathId":"%s","scope":"path","outcome":"%s","evidence":"real CloudGoat exploit outcome (score %s)"}]}' \
  "$TOP_ID" "$OUTCOME" "$TOP_SCORE" > "$TMP/report.json"
"$TMP/pg" importverdicts --file "$TMP/report.json" --api "$API_URL" || die "importverdicts failed"
ok "recorded $OUTCOME for $TOP_ID → calibration"
say "6. calibration after this run"
curl -s "$API_URL/validations" | jq -c '{metrics: .metrics, calibration: (.calibration | {samples,verdict,diagnosis,persistent})}' || true
echo
ok "done. 🔴 Remember: cd ~/labs/cloudgoat && cloudgoat destroy <scenario>"
