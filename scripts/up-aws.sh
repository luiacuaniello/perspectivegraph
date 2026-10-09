#!/usr/bin/env bash
# Start the stack reading your AWS account live: `make up-aws`.
#
#   AWS_PROFILE=<profile> AWS_REGION=<region> make up-aws
#   AWS_ROLE_ARN=<the role from deploy/aws>       assume it instead of reading as yourself
#   AWS_CONFIG_DIR=<dir>                          another directory than ~/.aws
#
# It runs docker-compose.aws.yml over the published images - that file says where the
# credentials come from - after checking what would otherwise fail only once the backend is
# up, as a connector error that does not say why: that the profile exists, and that the
# backend's user can read the files at all. Then it waits for the first pull and prints its
# outcome.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "up-aws: $*" >&2; exit 1; }
say() { echo "up-aws: $*"; }

# The busybox docker-compose.yml already pins, so the check pulls nothing new.
BUSYBOX=busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028
dir="${AWS_CONFIG_DIR:-$HOME/.aws}"

[ -d "$dir" ] || die "$dir does not exist. Configure a profile first (aws configure, or aws configure sso),
  or - with credentials only in your environment - create it empty: mkdir -m 700 $dir"

if [ -n "${AWS_PROFILE:-}" ]; then
  # A typo here otherwise surfaces as "failed to get shared config profile" in /connectors.
  # (Either file may be missing, which under pipefail must not read as "no such profile".)
  { cat "$dir/config" "$dir/credentials" 2>/dev/null || true; } | grep -Fqx -e "[profile $AWS_PROFILE]" -e "[$AWS_PROFILE]" ||
    die "no profile '$AWS_PROFILE' in $dir/config or $dir/credentials"
elif [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
  say "neither AWS_PROFILE nor AWS_ACCESS_KEY_ID is set: reading with the default profile"
fi
[ -n "${AWS_REGION:-}" ] || say "AWS_REGION is not set: the profile's region is used, and the pull fails if it names none"

# The backend runs as uid 65532 and a bind mount keeps the host's owners and modes, so on
# Linux a credentials file that is yours and 600 - how `aws configure` writes it - is one
# the backend cannot open. Found by doing what the SDK does, as that uid: entering the
# directory (no listing - the SDK opens files by name, so x is all it needs) and opening the
# files. Not by asking test -r: Docker Desktop reports the host's modes but lets every open
# through, so a mode check there refuses what the backend would in fact read.
unreadable=$(docker run --rm --user 65532:65532 -v "$dir:/aws:ro" "$BUSYBOX" sh -c '
  cd /aws 2>/dev/null || { echo "$0 (the directory)"; exit; }
  for f in /aws/config /aws/credentials /aws/sso/cache/*.json; do
    [ -e "$f" ] && ! cat "$f" >/dev/null 2>&1 && echo "$0${f#/aws}"
  done; true' "$dir")
if [ -n "$unreadable" ]; then
  die "the backend runs as uid 65532 and cannot read:
$(echo "$unreadable" | sed 's/^/  /')
  Grant that one uid read access, and nothing to anyone else:
    setfacl -m u:65532:x $dir
    setfacl -m u:65532:r $dir/config $dir/credentials
  (for an SSO profile also: setfacl -R -m u:65532:rX $dir/sso)"
fi

if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then as="the credentials in your environment"; else as="profile ${AWS_PROFILE:-default}"; fi
say "starting the stack with live AWS reads ($as${AWS_ROLE_ARN:+, assuming $AWS_ROLE_ARN})"
docker compose -f docker-compose.yml -f docker-compose.demo.yml -f docker-compose.aws.yml --profile app up -d

# The connectors pull once as the backend starts, then every CONNECTOR_INTERVAL.
say "waiting for the first pull (GET localhost:8081/connectors)"
# Every connector reports from the start, with "runs":0 until its first pull completes.
status='' pulled=''
for _ in $(seq 1 90); do
  status=$(curl -fsS localhost:8081/connectors 2>/dev/null || true)
  case "$status" in
    *'"runs":0}'*) ;;
    *'"runs":'*) pulled=1; break ;;
  esac
  sleep 2
done
[ -n "$pulled" ] || die "no pull completed within three minutes; see: docker compose logs backend"
case "$status" in
  *'"lastOk":false'*) die "the pull failed - the error is the AWS SDK's: $status" ;;
esac
say "the pull succeeded: $status"
say "the dashboard is on http://localhost:3000 - attack paths appear after the next analyzer pass (ANALYZER_INTERVAL, 30s)"
