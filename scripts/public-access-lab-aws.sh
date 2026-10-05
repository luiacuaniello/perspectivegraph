#!/usr/bin/env bash
#
# public-access-lab-aws.sh - S3 Block Public Access, set on a bucket and on the whole
# account, checked on a REAL AWS account with AWS as the referee.
#
# The custodian collector reads a bucket's own Block Public Access settings and, since
# 1.32.0, the account's: an aws.account resource, as Custodian's s3-public-block filter
# reports it. Two empty buckets carry a policy that lets anyone list and read them:
#
#   bucketblock   closed by its own RestrictPublicBuckets
#   accountblock  its own settings leave the policy in force; the account's
#                 RestrictPublicBuckets closes it
#
# AWS referees each one twice: GetBucketPolicyStatus says whether the policy alone is
# public, and an anonymous request - an unsigned listing of the bucket - says whether a
# stranger gets in (403 AccessDenied: no). The engine must agree with the second. Told
# nothing of the account's settings, it must call accountblock open: the false positive
# reading the account's settings removes.
#
# No stranger gets in. Each policy is put only once a setting already closes it, and the
# account's setting is given time to reach the Region before accountblock's own is
# relaxed. CONTROL=1 adds the one step that opens something: the account's setting is
# lifted and the referee asked again, so it is seen to answer "open" too - an empty bucket
# anyone may list, for about a minute, before its policy is deleted.
#
# The lab refuses to run on an account that already has account-level Block Public Access,
# so it never loosens one; the configuration it sets, it deletes on the way out.
#
# Cost: nothing - two empty buckets and a handful of requests.
#
#   PROFILE=pg-admin REGION=eu-north-1 ./scripts/public-access-lab-aws.sh
#   CONTROL=1 ... ./scripts/public-access-lab-aws.sh   # also see the referee answer "open"
#   ./scripts/public-access-lab-aws.sh --teardown      # clean a leaked lab

set -euo pipefail

PROFILE="${PROFILE:-pg-admin}"
REGION="${REGION:-eu-north-1}"
PREFIX="${PREFIX:-pg-bpa-lab}"
CONTROL="${CONTROL:-0}"

export AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" AWS_PAGER=""
say() { printf '%s\n' "$*" >&2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=""
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
# What the lab sets on the account: the two settings that close existing grants, and
# BlockPublicAcls. BlockPublicPolicy stays off, or the lab could not put its policies.
LAB_ACCOUNT_BLOCK='BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true'
LAB_ACCOUNT_JSON='{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":false,"RestrictPublicBuckets":true}'
CLOSED='BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true'
RELAXED='BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false'

account_block() { # the account's configuration as JSON, or "none"
  aws s3control get-public-access-block --account-id "$ACCOUNT" \
    --query PublicAccessBlockConfiguration --output json 2>/dev/null || echo none
}

same_json() { python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1]) == json.loads(sys.argv[2]) else 1)' "$1" "$2"; }

# ── Teardown ────────────────────────────────────────────────────────────────
# Buckets go first, with their policies, so that removing the account's setting afterwards
# opens nothing. Only the configuration this lab sets is removed.
teardown() {
  set +e
  say ""
  say "── tearing down ──────────────────────────────────────────────"
  for b in $(aws s3api list-buckets --query "Buckets[?starts_with(Name, '${PREFIX}-')].Name" --output text); do
    aws s3api delete-bucket-policy --bucket "$b" >/dev/null 2>&1
    aws s3api delete-bucket --bucket "$b" >/dev/null && say "  deleted bucket $b"
  done
  current=$(account_block)
  if [ "$current" != "none" ] && same_json "$current" "$LAB_ACCOUNT_JSON"; then
    aws s3control delete-public-access-block --account-id "$ACCOUNT" &&
      say "  deleted the account's Block Public Access configuration (the lab's)"
  elif [ "$current" != "none" ]; then
    say "  the account has a Block Public Access configuration this lab did not set: left as it is"
  fi
  [ -n "$WORK" ] && rm -rf "$WORK"
}

if [ "${1:-}" = "--teardown" ]; then
  teardown
  exit 0
fi

existing=$(account_block)
if [ "$existing" != "none" ]; then
  say "This account already has account-level Block Public Access:"
  say "$existing"
  say "The lab runs only where there is none, so that it never loosens one; nothing was changed."
  say "If it is a leaked lab's, ./scripts/public-access-lab-aws.sh --teardown removes it."
  exit 2
fi

WORK=$(mktemp -d)
trap teardown EXIT

retry() { # retry <attempts> <command...>
  local n="$1"; shift
  for _ in $(seq 1 "$n"); do
    if "$@" 2>"$WORK/retry.err"; then return 0; fi
    sleep 5
  done
  cat "$WORK/retry.err" >&2
  return 1
}

# new_bucket <name>: empty, closed by its own RestrictPublicBuckets, then given a policy
# that lets anyone list it and read its objects.
new_bucket() {
  local policy
  policy=$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"},{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}' "$1" "$1")
  aws s3api create-bucket --bucket "$1" --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
  aws s3api put-bucket-tagging --bucket "$1" --tagging 'TagSet=[{Key=pg-lab,Value=public-access}]'
  aws s3api put-public-access-block --bucket "$1" --public-access-block-configuration "$CLOSED"
  retry 12 aws s3api put-bucket-policy --bucket "$1" --policy "$policy"
}

# anon <bucket>: an unsigned listing of the bucket - "<HTTP status> <S3 error code>".
anon() {
  local code
  code=$(curl -s -o "$WORK/anon.xml" -w '%{http_code}' --max-time 20 "https://$1.s3.${REGION}.amazonaws.com/" || true)
  printf '%s %s' "$code" "$(sed -n 's:.*<Code>\([A-Za-z]*\)</Code>.*:\1:p' "$WORK/anon.xml" | head -1)"
}

# ── Build ───────────────────────────────────────────────────────────────────
say "── building the lab in ${REGION} ─────────────────────────────"
SUFFIX=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
BB="${PREFIX}-${SUFFIX}-bucketblock"
AB="${PREFIX}-${SUFFIX}-accountblock"

new_bucket "$BB"
say "  ${BB}: a public policy, closed by its own RestrictPublicBuckets"

aws s3control put-public-access-block --account-id "$ACCOUNT" --public-access-block-configuration "$LAB_ACCOUNT_BLOCK"
say "  the account: RestrictPublicBuckets and IgnorePublicAcls on; 90 s for them to reach ${REGION}…"
sleep 90

new_bucket "$AB"
# Only now, with the account's setting in force, is the bucket's own relaxed: from here the
# account's alone keeps strangers out.
aws s3api put-public-access-block --bucket "$AB" --public-access-block-configuration "$RELAXED"
say "  ${AB}: a public policy, its own RestrictPublicBuckets off - only the account's closes it"
sleep 15

# ── Referees ────────────────────────────────────────────────────────────────
BB_ANON=$(anon "$BB")
AB_ANON=$(anon "$AB")
python3 - "$WORK/public-access.json" "$ACCOUNT" "$BB" "$BB_ANON" "$AB" "$AB_ANON" <<'PY'
import json, subprocess, sys
out, account, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
def aws(*a):
    return json.loads(subprocess.run(["aws", *a, "--output", "json"], check=True, capture_output=True, text=True).stdout)
buckets = []
for name, anonymous in zip(rest[0::2], rest[1::2]):
    buckets.append({
        "name": name,
        "policy": aws("s3api", "get-bucket-policy", "--bucket", name)["Policy"],
        "bpa": aws("s3api", "get-public-access-block", "--bucket", name)["PublicAccessBlockConfiguration"],
        "aws_policy_public": aws("s3api", "get-bucket-policy-status", "--bucket", name)["PolicyStatus"]["IsPublic"],
        "anonymous": anonymous.strip(),
    })
account_bpa = aws("s3control", "get-public-access-block", "--account-id", account)["PublicAccessBlockConfiguration"]
json.dump({"account": account, "account_bpa": account_bpa, "buckets": buckets}, open(out, "w"), indent=2)
PY

status=0
say ""
say "── S3: the custodian collector against AWS ───────────────────"
(cd "$ROOT/backend" && PG_LAB_PUBLIC_ACCESS="$WORK/public-access.json" PG_LAB_ROWS="$WORK/rows.jsonl" \
  go test ./internal/ingestion/custodian/ -run TestBlockPublicAccessAgreesWithAWS -count=1 -v) >"$WORK/s3.out" 2>&1 || status=1
grep -E 'lab_test.go|^(--- |ok|FAIL)' "$WORK/s3.out" | sed 's/^ *lab_test.go:[0-9]*: /  /' >&2
# The record the dashboard's Accuracy page shows, disagreements included.
if [ -s "$WORK/rows.jsonl" ]; then
  python3 "$ROOT/scripts/lab-record.py" --lab public-access-lab-aws \
    --title "S3 Block Public Access, on a bucket and on the whole account" \
    --command "make public-access-lab-aws" --region "$REGION" --cost "free" --rows "$WORK/rows.jsonl"
fi

if [ "$CONTROL" = "1" ]; then
  say ""
  say "── control: the account's setting lifted ─────────────────────"
  aws s3control delete-public-access-block --account-id "$ACCOUNT"
  verdict=""
  for _ in $(seq 1 12); do
    verdict=$(anon "$AB")
    case "$verdict" in 200*) break ;; esac
    sleep 10
  done
  aws s3api delete-bucket-policy --bucket "$AB"
  if [ "${verdict%% *}" = "200" ]; then
    say "  PASS  without the account's setting a stranger lists ${AB} (${verdict}):"
    say "        the 403 above was the account's RestrictPublicBuckets. Policy deleted again."
  else
    say "  FAIL  the referee never answered open (${verdict}): it cannot tell open from closed"
    status=1
  fi
fi

say ""
say "─────────────────────────────────────────────────────────────"
if [ "$status" -eq 0 ]; then
  say "  PASS: on a real account, the engine agrees with AWS on what a stranger can reach"
  say "  when Block Public Access is set on the bucket and when it is set on the account."
else
  say "  FAIL: the engine and AWS disagree above - a false positive or a miss, found on"
  say "  real infrastructure."
fi
exit "$status"
