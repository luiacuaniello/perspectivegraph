#!/usr/bin/env bash
#
# reachability-lab-aws.sh - prove the reachability-precision claim on a REAL account.
#
# The engine's sharpest claim against every "open security group = exposed" scanner is
# that an open SG is necessary but NOT sufficient: the traffic also needs a route to an
# internet gateway. That claim is covered by a CI benchmark scenario today, but only
# against fixtures - JSON someone wrote. This stands up the smallest possible AWS
# topology that settles it against AWS itself.
#
# The lab is one variable wide, on purpose:
#
#   ONE security group, open 0.0.0.0/0, attached to BOTH instances.
#   Public subnet   -> route table with 0.0.0.0/0 -> internet gateway
#   Private subnet  -> route table with no default route at all
#
# So the only difference between the two boxes is the route table. If the engine marks
# both exposed it is doing SG-only reachability and the claim is false; if it marks only
# the public one, the claim holds on real data.
#
# Cost: the VPC, subnets, route tables, gateway and security group are free. The two
# t3.micro instances are free-tier eligible and live for the few minutes this takes;
# outside the free tier they are worth well under a cent. There is deliberately NO NAT
# gateway - a private subnet needs no route at all, and a NAT would quietly cost ~$30 a
# month. Everything is tagged and an EXIT trap tears it down even if this script dies.
#
#   PROFILE=pg-admin REGION=eu-north-1 ./scripts/reachability-lab-aws.sh
#   KEEP=1 ... ./scripts/reachability-lab-aws.sh   # leave the lab up to inspect it
#
# Tear a leaked lab down by hand at any time:
#   ./scripts/reachability-lab-aws.sh --teardown

set -euo pipefail

PROFILE="${PROFILE:-pg-admin}"
REGION="${REGION:-eu-north-1}"
TAG="${TAG:-pg-reach-test}"
CIDR="${CIDR:-10.42.0.0/16}"
KEEP="${KEEP:-0}"

aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }
say() { printf '%s\n' "$*" >&2; }

# ── Teardown ────────────────────────────────────────────────────────────────
# Ordered by dependency: instances, then the networking that references them.
# Every step tolerates "already gone" so a partial lab still cleans up fully.
teardown() {
  say ""
  say "── tearing down (tag: $TAG) ──"

  local ids
  ids=$(aws_ ec2 describe-instances \
    --filters "Name=tag:Project,Values=$TAG" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)
  if [ -n "${ids:-}" ]; then
    say "  terminating: $ids"
    aws_ ec2 terminate-instances --instance-ids $ids >/dev/null 2>&1 || true
    aws_ ec2 wait instance-terminated --instance-ids $ids 2>/dev/null || true
  fi

  local vpc
  vpc=$(aws_ ec2 describe-vpcs --filters "Name=tag:Project,Values=$TAG" \
    --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)
  if [ -z "${vpc:-}" ] || [ "$vpc" = "None" ]; then
    say "  no lab VPC left"
    return 0
  fi

  # Security groups (skip the VPC's default, which cannot be deleted).
  for sg in $(aws_ ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc" \
      --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text 2>/dev/null || true); do
    aws_ ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1 || true
  done
  for sn in $(aws_ ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" \
      --query 'Subnets[].SubnetId' --output text 2>/dev/null || true); do
    aws_ ec2 delete-subnet --subnet-id "$sn" >/dev/null 2>&1 || true
  done
  for rt in $(aws_ ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc" \
      --query 'RouteTables[?length(Associations[?Main==`true`])==`0`].RouteTableId' --output text 2>/dev/null || true); do
    aws_ ec2 delete-route-table --route-table-id "$rt" >/dev/null 2>&1 || true
  done
  for igw in $(aws_ ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpc" \
      --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null || true); do
    aws_ ec2 detach-internet-gateway --internet-gateway-id "$igw" --vpc-id "$vpc" >/dev/null 2>&1 || true
    aws_ ec2 delete-internet-gateway --internet-gateway-id "$igw" >/dev/null 2>&1 || true
  done
  aws_ ec2 delete-vpc --vpc-id "$vpc" >/dev/null 2>&1 || true
  say "  removed VPC $vpc and everything in it"
}

[ "${1:-}" = "--teardown" ] && { teardown; exit 0; }

# ── Build ───────────────────────────────────────────────────────────────────
trap 'if [ "$KEEP" = "1" ]; then say ""; say "KEEP=1: lab left running - tear down with: $0 --teardown"; else teardown; fi' EXIT

say "── building the lab in $REGION (profile: $PROFILE) ──"
tag_spec() { echo "ResourceType=$1,Tags=[{Key=Project,Value=$TAG},{Key=Name,Value=$2}]"; }

VPC=$(aws_ ec2 create-vpc --cidr-block "$CIDR" \
  --tag-specifications "$(tag_spec vpc "$TAG")" --query Vpc.VpcId --output text)
say "  vpc            $VPC"

IGW=$(aws_ ec2 create-internet-gateway \
  --tag-specifications "$(tag_spec internet-gateway "$TAG-igw")" \
  --query InternetGateway.InternetGatewayId --output text)
aws_ ec2 attach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC"
say "  igw            $IGW"

AZ=$(aws_ ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
PUB_SN=$(aws_ ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.42.1.0/24 --availability-zone "$AZ" \
  --tag-specifications "$(tag_spec subnet "$TAG-public")" --query Subnet.SubnetId --output text)
PRI_SN=$(aws_ ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.42.2.0/24 --availability-zone "$AZ" \
  --tag-specifications "$(tag_spec subnet "$TAG-private")" --query Subnet.SubnetId --output text)
say "  public subnet  $PUB_SN"
say "  private subnet $PRI_SN"

# The public subnet gets a default route to the gateway. The private one gets its own
# route table with LOCAL ROUTES ONLY - no default route, and deliberately no NAT.
PUB_RT=$(aws_ ec2 create-route-table --vpc-id "$VPC" \
  --tag-specifications "$(tag_spec route-table "$TAG-public-rt")" --query RouteTable.RouteTableId --output text)
aws_ ec2 create-route --route-table-id "$PUB_RT" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null
aws_ ec2 associate-route-table --route-table-id "$PUB_RT" --subnet-id "$PUB_SN" >/dev/null
PRI_RT=$(aws_ ec2 create-route-table --vpc-id "$VPC" \
  --tag-specifications "$(tag_spec route-table "$TAG-private-rt")" --query RouteTable.RouteTableId --output text)
aws_ ec2 associate-route-table --route-table-id "$PRI_RT" --subnet-id "$PRI_SN" >/dev/null
say "  routes         public -> igw, private -> local only (no NAT)"

# ONE group, wide open, shared by both instances: the variable under test is the route
# table, so everything else has to be identical.
SG=$(aws_ ec2 create-security-group --vpc-id "$VPC" --group-name "$TAG-open" \
  --description "Deliberately open to 0.0.0.0/0 for the reachability test" \
  --tag-specifications "$(tag_spec security-group "$TAG-open")" --query GroupId --output text)
aws_ ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 80 --cidr 0.0.0.0/0 >/dev/null
say "  security group $SG (open 0.0.0.0/0:80, on BOTH instances)"

AMI=$(aws_ ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
launch() { # subnet name -> instance id
  aws_ ec2 run-instances --image-id "$AMI" --instance-type t3.micro --count 1 \
    --subnet-id "$1" --security-group-ids "$SG" \
    --tag-specifications "$(tag_spec instance "$2")" \
    --query 'Instances[0].InstanceId' --output text
}
PUB_I=$(launch "$PUB_SN" "$TAG-public-box")
PRI_I=$(launch "$PRI_SN" "$TAG-private-box")
say "  instances      $PUB_I (public), $PRI_I (private)"

say ""
say "── waiting for both instances to register ──"
aws_ ec2 wait instance-running --instance-ids "$PUB_I" "$PRI_I"
say "  running"

cat >&2 <<EOF

── what the engine must say ──
  $PUB_I  (public subnet)   -> internet-exposed
  $PRI_I  (private subnet)  -> SUPPRESSED, despite the same wide-open security group

Collect it now:

  cd backend && AWS_PROFILE=$PROFILE go run ./cmd/perspectivegraph awscollect -region $REGION

EOF

if [ "$KEEP" = "1" ]; then
  say "KEEP=1: leaving the lab up. Run the command above, then tear down."
  trap - EXIT
  say ""
  say "Tear down with: $0 --teardown"
fi
