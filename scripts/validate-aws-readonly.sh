#!/usr/bin/env bash
#
# validate-aws-readonly.sh - run the live AWS connector against a REAL read-only
# account and show what it discovered. The honest "first contact with real data"
# check for the reachability-precision claim: the connector should flag genuinely
# internet-reachable instances as seeds and SUPPRESS the SG-open instances that sit
# in private subnets (naming *why* - NAT / transit gateway / egress-only IGW / NACL).
# It performs describe-* reads only; it never writes to the account.
#
#   AWS_REGION=eu-west-1 make validate-aws
#   AWS_REGION=eu-west-1 ROLE_ARN=arn:aws:iam::123456789012:role/pg-readonly make validate-aws
#   AWS_REGION=eu-west-1 INGEST_URL=http://localhost:8081 make validate-aws   # + push to a running stack
#
# Credentials come from the standard AWS chain (env vars / `aws configure` profile /
# SSO / instance role). Read-only grant: the AWS-managed SecurityAudit (or
# ViewOnlyAccess) policy is enough - it covers ec2:Describe* and
# iam:GetAccountAuthorizationDetails. ROLE_ARN optionally assumes a cross-account
# read-only role first (the "customer grants you a role" agentless model).
set -euo pipefail

REGION=${AWS_REGION:-${REGION:-}}
ROLE_ARN=${ROLE_ARN:-}
INGEST_URL=${INGEST_URL:-}
GO=${GO:-go}; export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.12}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
die() { echo "ERROR: $*" >&2; exit 1; }

[ -n "$REGION" ] || die "set AWS_REGION (or REGION), e.g. AWS_REGION=eu-west-1 make validate-aws"
command -v "$GO" >/dev/null 2>&1 || die "go not found (needed to build the connector)"

# Friendly, read-only preflight: which account/identity are we about to read?
if command -v aws >/dev/null 2>&1; then
  acct="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
  if [ -n "$acct" ]; then
    echo "preflight: authenticated to AWS account $acct (region $REGION)"
  else
    echo "preflight: aws CLI present but no identity resolved yet - the SDK will try the credential chain"
  fi
else
  echo "preflight: aws CLI not found; the SDK will still use the ambient credential chain"
fi

echo "building the perspectivegraph CLI ..."
$GO build -o "$TMP/pg" "$ROOT/backend/cmd/perspectivegraph" 2>/dev/null \
  || (cd "$ROOT/backend" && $GO build -o "$TMP/pg" ./cmd/perspectivegraph) \
  || die "CLI build failed"

args=(awscollect -region "$REGION")
[ -n "$ROLE_ARN" ]   && args+=(-role "$ROLE_ARN")
[ -n "$INGEST_URL" ] && args+=(-ingest "$INGEST_URL")

echo "running: pg ${args[*]}"
echo
"$TMP/pg" "${args[@]}"

echo
echo "validation: eyeball the 'internet-exposed seeds' vs 'SG-open but NOT exposed'"
echo "lists above against what you know of the account. Every instance in the second"
echo "list is a false positive the reachability layer removed - that is the claim under"
echo "test. Re-run with INGEST_URL=... to score full attack paths in a running stack."
