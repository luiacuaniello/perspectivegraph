#!/usr/bin/env bash
#
# boundary-lab-aws.sh - the engine's first genuine FALSE POSITIVE, and the check that it
# stays closed.
#
# This lab was built to EXPOSE a bug: the engine read identity policies and reported a
# principal as able to escalate whenever it held a known privesc primitive, without
# evaluating permission boundaries. `GetAccountAuthorizationDetails` returns the
# boundary; the connector's role struct dropped it. So a role whose policy granted
# `iam:AttachUserPolicy` but whose boundary forbade it was, to the engine, an
# escalation - and to AWS, nothing of the kind.
#
# That is fixed: the connector now carries `PermissionsBoundary` through (fetching the
# boundary document when the bundle does not include it), and the evaluator intersects
# it. The lab is now the REGRESSION TEST for that fix, run against real AWS.
#
# It is one variable wide, on purpose:
#
#   TWO roles, byte-identical inline policy granting real privesc primitives.
#   unbounded -> no permissions boundary          -> AWS: ALLOWED,  engine: ESCALATES
#   bounded   -> permissions boundary (s3:Get*)   -> AWS: DENIED,   engine: no privesc
#
# So the only difference is the boundary. The unbounded role is the control, and it is
# what makes the result mean anything: without a role both sides ALLOW, an engine that
# had simply stopped emitting escalation edges would look equally convincing.
#
# Both verdicts are produced here for real - the engine by running the live connector
# over the account, AWS by `iam:SimulatePrincipalPolicy` - and the script FAILS if they
# disagree on either role.
#
# Cost: ZERO, and not merely free-tier. IAM roles, inline policies and managed policies
# are free on every AWS account, with no time limit and no metered dimension. Nothing
# here launches compute, allocates an address or stores data. Every check is
# `iam:SimulatePrincipalPolicy`, a dry run that evaluates policy without performing
# anything. An EXIT trap tears the lab down even if this script dies.
#
#   PROFILE=pg-admin REGION=eu-north-1 ./scripts/boundary-lab-aws.sh
#   KEEP=1 ... ./scripts/boundary-lab-aws.sh    # leave the lab up to inspect it
#
# Tear a leaked lab down by hand at any time:
#   ./scripts/boundary-lab-aws.sh --teardown

set -euo pipefail

PROFILE="${PROFILE:-pg-admin}"
REGION="${REGION:-eu-north-1}"
PREFIX="${PREFIX:-pg-boundary-lab}"
KEEP="${KEEP:-0}"

BOUNDED="${PREFIX}-bounded"
UNBOUNDED="${PREFIX}-unbounded"
BOUNDARY="${PREFIX}-boundary"

aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }
say() { printf '%s\n' "$*" >&2; }

ACCOUNT="$(aws_ sts get-caller-identity --query Account --output text)"
BOUNDARY_ARN="arn:aws:iam::${ACCOUNT}:policy/${BOUNDARY}"

# The privesc grant. Account-wide on purpose: the engine's detector distinguishes broad
# from resource-scoped grants, and a broad one is the unambiguous claim to put to AWS.
PRIVESC_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey"],
    "Resource": "*"
  }]
}'

# The boundary. A boundary caps effective permissions to the INTERSECTION of itself and
# the identity policy, so omitting the iam:* actions is what neutralises the grant - no
# explicit Deny needed, which is exactly how boundaries are used in the wild and exactly
# the case a policy reader that ignores boundaries gets wrong.
BOUNDARY_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:Get*", "ec2:Describe*"],
    "Resource": "*"
  }]
}'

# EC2 as the trust principal keeps the lab shaped like the real finding: an instance role.
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# ── Teardown ────────────────────────────────────────────────────────────────
# Ordered by dependency: the inline policies and the roles that reference the boundary,
# then the boundary policy itself. Every step tolerates "already gone" so the trap is
# safe to run twice.
teardown() {
  say ""
  say "── tearing down ──────────────────────────────────────────────"
  for role in "$BOUNDED" "$UNBOUNDED"; do
    aws_ iam delete-role-policy --role-name "$role" --policy-name privesc >/dev/null 2>&1 || true
    aws_ iam delete-role --role-name "$role" >/dev/null 2>&1 \
      && say "  deleted role $role" || true
  done
  # Non-default versions block a policy delete; we never create any, but be defensive.
  for v in $(aws_ iam list-policy-versions --policy-arn "$BOUNDARY_ARN" \
               --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null || true); do
    aws_ iam delete-policy-version --policy-arn "$BOUNDARY_ARN" --version-id "$v" >/dev/null 2>&1 || true
  done
  aws_ iam delete-policy --policy-arn "$BOUNDARY_ARN" >/dev/null 2>&1 \
    && say "  deleted policy $BOUNDARY" || true
  say "  done - the account is back to where it started"
}

if [ "${1:-}" = "--teardown" ]; then
  teardown
  exit 0
fi

# Never leave IAM entities behind, even on failure or Ctrl-C.
if [ "$KEEP" != "1" ]; then
  trap teardown EXIT
fi

# ── Build ───────────────────────────────────────────────────────────────────
say "── building the boundary lab in account ${ACCOUNT} ───────────"

# Start from a clean slate in case a previous run leaked.
teardown >/dev/null 2>&1 || true

aws_ iam create-policy \
  --policy-name "$BOUNDARY" \
  --policy-document "$BOUNDARY_POLICY" \
  --description "PerspectiveGraph boundary lab - caps effective permissions to s3:Get*/ec2:Describe*" \
  >/dev/null
say "  created boundary policy $BOUNDARY (allows only s3:Get*, ec2:Describe*)"

for role in "$UNBOUNDED" "$BOUNDED"; do
  if [ "$role" = "$BOUNDED" ]; then
    aws_ iam create-role --role-name "$role" \
      --assume-role-policy-document "$TRUST_POLICY" \
      --permissions-boundary "$BOUNDARY_ARN" \
      --tags Key=pg-lab,Value=boundary >/dev/null
    say "  created role $role           WITH the boundary"
  else
    aws_ iam create-role --role-name "$role" \
      --assume-role-policy-document "$TRUST_POLICY" \
      --tags Key=pg-lab,Value=boundary >/dev/null
    say "  created role $role         (no boundary - the control)"
  fi
  # Identical grant on both roles: the boundary is the only difference.
  aws_ iam put-role-policy --role-name "$role" \
    --policy-name privesc --policy-document "$PRIVESC_POLICY" >/dev/null
done
say "  both roles granted the SAME policy: iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreateAccessKey on *"

# IAM is eventually consistent; a simulation run immediately after creation can still
# read the pre-creation state and would report a misleading answer.
say ""
say "  waiting for IAM to converge…"
sleep 12

say ""
say "── ENGINE vs AWS ────────────────────────────────────────────"
say "  Both roles hold iam:AttachUserPolicy on * - a textbook privesc primitive - and"
say "  differ only in the boundary. The engine is run over this very account (live"
say "  connector, read-only) and AWS is asked with SimulatePrincipalPolicy; the two"
say "  verdicts go side by side. Before the boundary fix the engine called BOTH roles"
say "  escalating and this comparison failed on the bounded one."
say ""

cd "$(dirname "$0")/../backend"
status=0
AWS_PROFILE="$PROFILE" CGO_ENABLED=0 go run ./cmd/perspectivegraph redteam \
  -region "$REGION" -compare \
  -principal "arn:aws:iam::${ACCOUNT}:role/${UNBOUNDED},arn:aws:iam::${ACCOUNT}:role/${BOUNDED}" \
  2>&1 | sed 's/^/  /' || status=$?

say ""
say "─────────────────────────────────────────────────────────────"
if [ "$status" -eq 0 ]; then
  say "  PASS: the engine and AWS agree on BOTH roles - the control escalates, the"
  say "  bounded one does not. The permission-boundary false positive is closed, and"
  say "  proven closed against real AWS with a dry run and no exploitation."
else
  say "  FAIL: the engine and AWS disagree. Each disagreement is a false positive (the"
  say "  engine over-reporting) or a miss (the engine failing to report a real"
  say "  escalation) - both are real findings. See the table above."
fi
say ""
if [ "$KEEP" = "1" ]; then
  say "  KEEP=1: the lab is still up. Tear it down with:"
  say "    ./scripts/boundary-lab-aws.sh --teardown"
fi
exit "$status"
