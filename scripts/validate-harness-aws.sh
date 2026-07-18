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
# A common slip: passing an availability zone (us-east-1a) where a region (us-east-1) is
# meant - CloudGoat prints the AZ. Strip a trailing zone letter so the SDK is happy.
case "$REGION" in
  *-[0-9][a-z]) NORM=${REGION%?}; warn "REGION '$REGION' looks like an availability zone; using region '$NORM'"; REGION=$NORM ;;
esac
[ -n "$ROLE_ARN" ] || die "set ROLE_ARN to your read-only role (the connector assumes it)"
curl -sf "$API_URL/healthz" >/dev/null 2>&1 || die "stack unreachable at $API_URL (run: make up-full)"
[ "${CONFIRM:-}" = "i-understand-internet-exposure" ] || die \
  "this briefly exposes a deliberately-vulnerable EC2 to 0.0.0.0/0. Re-run with CONFIRM=i-understand-internet-exposure once you accept that."

# ── Find the scenario's security group (or take SG_ID) ───────────────
say "1. locate the CloudGoat instance + its security group in $REGION"
if [ -z "$SG_ID" ]; then
  # CloudGoat scenarios tag instances inconsistently - some `cg-*`, some `CloudGoat*` - so
  # match both. Capture stderr so a failed call (bad region, expired creds, missing grant)
  # yields a clear message instead of set -e/pipefail killing the script with exit 255.
  if ! insts=$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=cg-*,CloudGoat*" "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[].SecurityGroups[].GroupId' --output text 2>&1); then
    die "aws describe-instances failed in region '$REGION': $(printf '%s' "$insts" | head -1)"
  fi
  SG_ID=$(printf '%s' "$insts" | tr '\t' '\n' | grep -E '^sg-' | sort -u | head -1)
fi
if [ -z "$SG_ID" ]; then
  warn "no CloudGoat instance auto-detected in $REGION. Running instances there:"
  aws ec2 describe-instances --region "$REGION" --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`].Value|[0],SG:SecurityGroups[0].GroupId}' --output text 2>/dev/null | sed 's/^/    /' || true
  die "pass SG_ID=sg-... explicitly (from the list above or the CloudGoat output), or check the region"
fi
ok "security group: $SG_ID"

# The engine ids the internet-exposed seed by the instance's Name tag, so capture it: it is
# how step 4 tells THIS scenario's path from any pre-existing graph data (a shared stack may
# already hold demo or other real topology). Empty is tolerated (step 4 falls back).
INSTANCE_NAME=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=instance.group-id,Values=$SG_ID" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].Tags[?Key==`Name`].Value|[0]' --output text 2>/dev/null)
[ "$INSTANCE_NAME" = "None" ] && INSTANCE_NAME=""
ok "scenario seed: ${INSTANCE_NAME:-<unnamed - will match any new internet seed>}"

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
say "4. wait for the analyzer, then find THIS scenario's path (by its real seed name)"
sleep "$ANALYZER_WAIT"
# Match paths by the scenario instance's actual name, not a broad pattern - a shared stack
# may already hold demo/other topology, and matching those would record a verdict against
# the wrong path. limit is generous so a low-priority scenario path is not cut off.
ALL=$(curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ attackPaths(limit:200){ id score priority nodes { name } } }"}')
if [ -z "$INSTANCE_NAME" ]; then
  die "no instance name to match on; cannot isolate the scenario's path from other graph data"
fi
PATHS=$(printf '%s' "$ALL" | jq -c --arg seed "$INSTANCE_NAME" \
  '[.data.attackPaths[] | select(([.nodes[].name] | index($seed)) != null) | {id, score, priority, route: ([.nodes[].name] | join(" -> "))}]')
n=$(printf '%s' "$PATHS" | jq 'length')
if [ "${n:-0}" -eq 0 ]; then
  warn "no scored path from the scenario's instance ('$INSTANCE_NAME') reached a sensitive asset."
  warn "That is a real finding, not a harness bug: the engine seeds from internet exposure, but"
  warn "this scenario's escalation typically starts from leaked credentials (a different threat"
  warn "model), and its goal may be an S3 bucket the connector does not read yet. Raw subgraph:"
  warn "  (cd backend && go run ./cmd/perspectivegraph awscollect -region $REGION -role $ROLE_ARN -json) | jq ."
  exit 0
fi
ok "$n path(s) from the scenario:"
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
