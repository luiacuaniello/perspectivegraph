#!/usr/bin/env bash
#
# entrypoints-lab-aws.sh - the 1.29.0 entry points, checked on a REAL AWS account, with
# AWS as the referee wherever AWS will give an answer.
#
# Each feature gets resources built to sit on either side of its rule, and a verdict that
# does not come from the engine:
#
#   S3 bucket policies  AWS's own judgement, GetBucketPolicyStatus.IsPublic, against the
#                       engine's reading of the same policy. Ten policies, public and not.
#   Lambda              an unauthenticated request to each function URL: 403 means AWS
#                       refuses strangers, anything else means it let the request through.
#                       Every function has reserved concurrency 0, so nothing ever runs.
#                       Then the open function's URL is deleted and the engine must retract.
#   ECS + ports         Fargate services with desiredCount 0 - no task, no address, no cost -
#                       in a routed, an unrouted and an ACL-filtered subnet. No oracle here:
#                       the expectations are AWS's documented routing rules.
#   Load balancers      an internet-facing and an internal application load balancer, the
#                       first forwarding to an ECS service in a private subnet and to a Lambda
#                       function: a plain HTTP request to each DNS name says which one the
#                       internet reaches.
#   API Gateway         an HTTP API with an open route and one behind a JWT authorizer, a
#                       REST API with an open method, and one whose policy denies everyone
#                       outside a documentation range: an unauthenticated request to each
#                       route says which ones answer (401 or 403 is closed).
#   GitHub OIDC         a role pinned to one repository (an identity provider that is no
#                       entry point), and an attempt at a role open to every repository,
#                       which AWS is documented to refuse.
#
# The engine reads the account through the live connector as PerspectiveGraphReadOnly,
# whose only policy is SecurityAudit - so the run also proves the new feeds need nothing
# more. S3 is Custodian's to report: the bundle is assembled from the same API answers
# Custodian records (`Policy`, `c7n:PublicAccessBlock`) and parsed by the custodian
# collector in an opt-in Go test.
#
# Cost: a few cents. The two load balancers bill by the hour - about USD 0.03 an hour
# together, with the public one's two IPv4 addresses - for the minutes the lab is up.
# Everything else is free: VPCs, subnets, route tables, NACLs, security groups, an internet
# gateway, IAM roles, an OIDC provider, empty buckets, an ECS cluster with idle services and
# Lambda functions that never run. No instance, no NAT gateway. Every public-looking bucket policy sits behind RestrictPublicBuckets, so no
# stranger can use it, and every bucket is empty. An EXIT trap tears it all down.
#
#   PROFILE=pg-admin REGION=eu-north-1 ./scripts/entrypoints-lab-aws.sh
#   KEEP=1 ... ./scripts/entrypoints-lab-aws.sh    # leave the lab up to inspect it
#   ./scripts/entrypoints-lab-aws.sh --teardown    # clean a leaked lab

set -euo pipefail

PROFILE="${PROFILE:-pg-admin}"
REGION="${REGION:-eu-north-1}"
PREFIX="${PREFIX:-pg-entry-lab}"
KEEP="${KEEP:-0}"
READONLY_ROLE="${READONLY_ROLE:-PerspectiveGraphReadOnly}"

export AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" AWS_PAGER=""
say() { printf '%s\n' "$*" >&2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=""
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
GH_HOST="token.actions.githubusercontent.com"
GH_PROVIDER="arn:aws:iam::${ACCOUNT}:oidc-provider/${GH_HOST}"
ROLES=(task fn grantee gh-pinned gh-open)
FUNCTIONS=(open urlonly iam private)

tag_filter() { echo "Name=tag:pg-lab,Values=entrypoints"; }

# ── Teardown ────────────────────────────────────────────────────────────────
# Everything the build makes carries the prefix or the pg-lab=entrypoints tag, so teardown
# finds it without a state file, and every step tolerates "already gone".
teardown() {
  set +e
  say ""
  say "── tearing down ──────────────────────────────────────────────"
  if aws ecs describe-clusters --clusters "$PREFIX" --query 'clusters[?status==`ACTIVE`]' --output text | grep -q .; then
    for s in $(aws ecs list-services --cluster "$PREFIX" --query 'serviceArns[]' --output text); do
      aws ecs delete-service --cluster "$PREFIX" --service "$s" --force >/dev/null
    done
    for _ in $(seq 1 30); do
      [ -z "$(aws ecs list-services --cluster "$PREFIX" --query 'serviceArns[]' --output text)" ] && break
      sleep 5
    done
    aws ecs delete-cluster --cluster "$PREFIX" >/dev/null && say "  deleted ECS cluster and services"
  fi
  for lb in $(aws elbv2 describe-load-balancers --query "LoadBalancers[?starts_with(LoadBalancerName, '${PREFIX}-')].LoadBalancerArn" --output text 2>/dev/null); do
    aws elbv2 delete-load-balancer --load-balancer-arn "$lb" && say "  deleted load balancer ${lb#*loadbalancer/app/}"
    aws elbv2 wait load-balancers-deleted --load-balancer-arns "$lb"
  done
  # A target group stays "in use" for a while after its load balancer is gone.
  for tg in $(aws elbv2 describe-target-groups --query "TargetGroups[?starts_with(TargetGroupName, '${PREFIX}-')].TargetGroupArn" --output text 2>/dev/null); do
    for _ in $(seq 1 24); do
      aws elbv2 delete-target-group --target-group-arn "$tg" 2>/dev/null && { say "  deleted target group ${tg#*targetgroup/}"; break; }
      sleep 5
    done
  done
  for td in $(aws ecs list-task-definitions --family-prefix "$PREFIX" --query 'taskDefinitionArns[]' --output text); do
    aws ecs deregister-task-definition --task-definition "$td" >/dev/null
    aws ecs delete-task-definitions --task-definitions "$td" >/dev/null 2>&1
  done
  for api in $(aws apigatewayv2 get-apis --query "Items[?starts_with(Name, '${PREFIX}-')].ApiId" --output text 2>/dev/null); do
    aws apigatewayv2 delete-api --api-id "$api" && say "  deleted HTTP API $api"
  done
  for api in $(aws apigateway get-rest-apis --query "items[?starts_with(name, '${PREFIX}-')].id" --output text 2>/dev/null); do
    # AWS takes one DeleteRestApi call every 30 seconds per account.
    for _ in 1 2 3 4; do
      aws apigateway delete-rest-api --rest-api-id "$api" 2>/dev/null && { say "  deleted REST API $api"; break; }
      sleep 31
    done
  done
  for f in "${FUNCTIONS[@]}"; do
    aws lambda delete-function --function-name "${PREFIX}-${f}" >/dev/null 2>&1 && say "  deleted function ${PREFIX}-${f}"
  done
  for b in $(aws s3api list-buckets --query "Buckets[?starts_with(Name, '${PREFIX}-')].Name" --output text); do
    aws s3api delete-bucket-policy --bucket "$b" >/dev/null 2>&1
    aws s3api delete-bucket --bucket "$b" >/dev/null && say "  deleted bucket $b"
  done
  for r in "${ROLES[@]}"; do
    aws iam delete-role --role-name "${PREFIX}-${r}" >/dev/null 2>&1 && say "  deleted role ${PREFIX}-${r}"
  done
  if aws iam list-open-id-connect-provider-tags --open-id-connect-provider-arn "$GH_PROVIDER" \
       --query "Tags[?Key=='pg-lab'].Value" --output text 2>/dev/null | grep -q entrypoints; then
    aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$GH_PROVIDER" && say "  deleted the GitHub OIDC provider"
  fi
  vpc=$(aws ec2 describe-vpcs --filters "$(tag_filter)" --query 'Vpcs[0].VpcId' --output text)
  if [ "$vpc" != "None" ] && [ -n "$vpc" ]; then
    # Idle Fargate services leave no interfaces, but a deleted load balancer takes minutes
    # to let go of its own.
    for _ in $(seq 1 90); do
      [ -z "$(aws ec2 describe-network-interfaces --filters Name=vpc-id,Values="$vpc" --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)" ] && break
      sleep 5
    done
    for sn in $(aws ec2 describe-subnets --filters Name=vpc-id,Values="$vpc" --query 'Subnets[].SubnetId' --output text); do
      aws ec2 delete-subnet --subnet-id "$sn"
    done
    for rt in $(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$vpc" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text); do
      aws ec2 delete-route-table --route-table-id "$rt"
    done
    for acl in $(aws ec2 describe-network-acls --filters Name=vpc-id,Values="$vpc" Name=default,Values=false --query 'NetworkAcls[].NetworkAclId' --output text); do
      aws ec2 delete-network-acl --network-acl-id "$acl"
    done
    # A group another one names in its rules cannot go first: retry until none is left.
    for _ in 1 2 3 4; do
      for sg in $(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$vpc" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text); do
        aws ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1
      done
      [ -z "$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$vpc" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text)" ] && break
      sleep 5
    done
    for igw in $(aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values="$vpc" --query 'InternetGateways[].InternetGatewayId' --output text); do
      aws ec2 detach-internet-gateway --internet-gateway-id "$igw" --vpc-id "$vpc"
      aws ec2 delete-internet-gateway --internet-gateway-id "$igw"
    done
    aws ec2 delete-vpc --vpc-id "$vpc" && say "  deleted the lab VPC"
  fi
  # The first ECS cluster in an account creates ECS's service-linked role; leave the account
  # as the lab found it. Deleting one is a task AWS runs afterwards, and Elastic Load
  # Balancing's fails while the deleted load balancers are still being cleaned up - so wait
  # for the outcome, and say so when it failed rather than report a deletion that did not
  # happen.
  delete_slr() { # delete_slr <role> <service>
    local task state=FAILED
    task=$(aws iam delete-service-linked-role --role-name "$1" --query DeletionTaskId --output text 2>/dev/null) || return 0
    for _ in $(seq 1 12); do
      # A task just created can be unknown for a moment: keep asking.
      state=$(aws iam get-service-linked-role-deletion-status --deletion-task-id "$task" --query Status --output text 2>/dev/null)
      case "$state" in SUCCEEDED|FAILED) break ;; esac
      sleep 5
    done
    if [ "$state" = SUCCEEDED ]; then
      say "  deleted $2's service-linked role, which the lab created"
    else
      say "  $2's service-linked role, which the lab created, is still in use ($state); delete it later with"
      say "    aws iam delete-service-linked-role --role-name $1"
    fi
  }
  if [ "${SLR_BEFORE:-yes}" = "no" ]; then
    delete_slr AWSServiceRoleForECS ECS
  fi
  if [ "${ELB_SLR_BEFORE:-yes}" = "no" ]; then
    delete_slr AWSServiceRoleForElasticLoadBalancing "Elastic Load Balancing"
  fi
  [ -n "$WORK" ] && rm -rf "$WORK"
  say "  done"
  set -e
}

if [ "${1:-}" = "--teardown" ]; then
  teardown
  exit 0
fi
if [ "$KEEP" != "1" ]; then
  trap teardown EXIT
fi
teardown >/dev/null 2>&1 || true
WORK=$(mktemp -d) # after the clean slate, which removes the previous run's

retry() { # retry <attempts> <command...>: IAM is eventually consistent, so new roles fail at first
  local n="$1"; shift
  for _ in $(seq 1 "$n"); do
    if "$@" 2>"$WORK/retry.err"; then return 0; fi
    sleep 5
  done
  cat "$WORK/retry.err" >&2
  return 1
}

say "── building the entry-points lab in ${REGION} ──────────────────"

# ── IAM ─────────────────────────────────────────────────────────────────────
trust() { printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"%s"},"Action":"sts:AssumeRole"}]}' "$1"; }
aws iam create-role --role-name "${PREFIX}-task" --assume-role-policy-document "$(trust ecs-tasks.amazonaws.com)" --tags Key=pg-lab,Value=entrypoints >/dev/null
aws iam create-role --role-name "${PREFIX}-fn" --assume-role-policy-document "$(trust lambda.amazonaws.com)" --tags Key=pg-lab,Value=entrypoints >/dev/null
aws iam create-role --role-name "${PREFIX}-grantee" --assume-role-policy-document "$(trust ec2.amazonaws.com)" --tags Key=pg-lab,Value=entrypoints >/dev/null
TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/${PREFIX}-task"
FN_ROLE="arn:aws:iam::${ACCOUNT}:role/${PREFIX}-fn"
GRANTEE="arn:aws:iam::${ACCOUNT}:role/${PREFIX}-grantee"
say "  roles: task, function execution, bucket grantee"

if ! aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$GH_PROVIDER" >/dev/null 2>&1; then
  aws iam create-open-id-connect-provider --url "https://${GH_HOST}" --client-id-list sts.amazonaws.com \
    --tags Key=pg-lab,Value=entrypoints >/dev/null
  say "  GitHub Actions OIDC provider (created for the lab)"
fi
gh_trust() { # gh_trust <condition JSON>
  printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"%s"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":%s}]}' "$GH_PROVIDER" "$1"
}
# JSON lives in single-quoted variables, and assignments from $(...) go unquoted: macOS's
# bash 3.2 mangles quotes nested inside a double-quoted "$(...)".
PINNED='{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:pg-lab-example/demo:*"}}'
OPEN='{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}'
PINNED_DOC=$(gh_trust "$PINNED")
OPEN_DOC=$(gh_trust "$OPEN")
aws iam create-role --role-name "${PREFIX}-gh-pinned" --tags Key=pg-lab,Value=entrypoints \
  --assume-role-policy-document "$PINNED_DOC" >/dev/null
say "  role gh-pinned: trusts GitHub Actions for repo:pg-lab-example/demo only"
GH_OPEN="refused"
if aws iam create-role --role-name "${PREFIX}-gh-open" --tags Key=pg-lab,Value=entrypoints \
     --assume-role-policy-document "$OPEN_DOC" \
     >/dev/null 2>"$WORK/gh-open.err"; then
  GH_OPEN="accepted"
  say "  role gh-open: AWS ACCEPTED a trust open to every repository (it carries no permissions)"
else
  say "  role gh-open: AWS refused a trust open to every repository - $(head -c 160 "$WORK/gh-open.err" | tr '\n' ' ')"
fi

# ── Network ─────────────────────────────────────────────────────────────────
tags() { echo "ResourceType=$1,Tags=[{Key=pg-lab,Value=entrypoints},{Key=Name,Value=${PREFIX}-$2}]"; }
AZ="${REGION}a"
VPC=$(aws ec2 create-vpc --cidr-block 10.42.0.0/16 --tag-specifications "$(tags vpc vpc)" --query Vpc.VpcId --output text)
IGW=$(aws ec2 create-internet-gateway --tag-specifications "$(tags internet-gateway igw)" --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC"
subnet() { aws ec2 create-subnet --vpc-id "$VPC" --cidr-block "$1" --availability-zone "$AZ" --tag-specifications "$(tags subnet "$2")" --query Subnet.SubnetId --output text; }
SN_PUBLIC=$(subnet 10.42.1.0/24 public)
SN_PRIVATE=$(subnet 10.42.2.0/24 private)
SN_ACL=$(subnet 10.42.3.0/24 acl)
RT_PUBLIC=$(aws ec2 create-route-table --vpc-id "$VPC" --tag-specifications "$(tags route-table public)" --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id "$RT_PUBLIC" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null
aws ec2 associate-route-table --route-table-id "$RT_PUBLIC" --subnet-id "$SN_PUBLIC" >/dev/null
aws ec2 associate-route-table --route-table-id "$RT_PUBLIC" --subnet-id "$SN_ACL" >/dev/null
RT_PRIVATE=$(aws ec2 create-route-table --vpc-id "$VPC" --tag-specifications "$(tags route-table private)" --query RouteTable.RouteTableId --output text)
aws ec2 associate-route-table --route-table-id "$RT_PRIVATE" --subnet-id "$SN_PRIVATE" >/dev/null
# The ACL subnet lets in 443 and nothing else: rule 100 allows it, the default * entry denies the rest.
ACL=$(aws ec2 create-network-acl --vpc-id "$VPC" --tag-specifications "$(tags network-acl acl)" --query NetworkAcl.NetworkAclId --output text)
aws ec2 create-network-acl-entry --network-acl-id "$ACL" --ingress --rule-number 100 --protocol tcp --port-range From=443,To=443 --cidr-block 0.0.0.0/0 --rule-action allow
aws ec2 create-network-acl-entry --network-acl-id "$ACL" --egress --rule-number 100 --protocol -1 --cidr-block 0.0.0.0/0 --rule-action allow
ASSOC=$(aws ec2 describe-network-acls --filters Name=association.subnet-id,Values="$SN_ACL" --query "NetworkAcls[0].Associations[?SubnetId=='${SN_ACL}'].NetworkAclAssociationId" --output text)
aws ec2 replace-network-acl-association --association-id "$ASSOC" --network-acl-id "$ACL" >/dev/null
sg() { # sg <name> <ip-permissions JSON>
  local id; id=$(aws ec2 create-security-group --vpc-id "$VPC" --group-name "${PREFIX}-$1" --description "PerspectiveGraph entry-points lab" --tag-specifications "$(tags security-group "$1")" --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id "$id" --ip-permissions "$2" >/dev/null
  echo "$id"
}
WEB='[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
SSHWEB='[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]},{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
ICMP='[{"IpProtocol":"icmp","FromPort":-1,"ToPort":-1,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
SG_WEB=$(sg web "$WEB")
SG_SSHWEB=$(sg ssh-web "$SSHWEB")
SG_ICMP=$(sg icmp "$ICMP")
say "  VPC with a routed, an unrouted and an ACL-filtered (443 only) subnet; security groups for 443, 22+443, ICMP"

# ── Load balancers ──────────────────────────────────────────────────────────
# An application load balancer needs subnets in two zones.
ELB_SLR_BEFORE=$(aws iam get-role --role-name AWSServiceRoleForElasticLoadBalancing >/dev/null 2>&1 && echo yes || echo no)
subnet_b() { aws ec2 create-subnet --vpc-id "$VPC" --cidr-block "$1" --availability-zone "${REGION}b" --tag-specifications "$(tags subnet "$2")" --query Subnet.SubnetId --output text; }
SN_PUBLIC_B=$(subnet_b 10.42.4.0/24 public-b)
SN_PRIVATE_B=$(subnet_b 10.42.5.0/24 private-b)
aws ec2 associate-route-table --route-table-id "$RT_PUBLIC" --subnet-id "$SN_PUBLIC_B" >/dev/null
aws ec2 associate-route-table --route-table-id "$RT_PRIVATE" --subnet-id "$SN_PRIVATE_B" >/dev/null
SG_ALB=$(sg alb '[{"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]')
APP=$(printf '[{"IpProtocol":"tcp","FromPort":80,"ToPort":80,"UserIdGroupPairs":[{"GroupId":"%s"}]}]' "$SG_ALB")
SG_APP=$(sg app "$APP")
alb() { # alb <name> <scheme> <subnet> <subnet>
  aws elbv2 create-load-balancer --name "${PREFIX}-$1" --type application --scheme "$2" --subnets "$3" "$4" \
    --security-groups "$SG_ALB" --tags Key=pg-lab,Value=entrypoints --query 'LoadBalancers[0].LoadBalancerArn' --output text
}
ALB_PUB=$(alb pub internet-facing "$SN_PUBLIC" "$SN_PUBLIC_B")
ALB_INT=$(alb int internal "$SN_PRIVATE" "$SN_PRIVATE_B")
TG_SVC=$(aws elbv2 create-target-group --name "${PREFIX}-svc" --target-type ip --protocol HTTP --port 80 --vpc-id "$VPC" \
  --tags Key=pg-lab,Value=entrypoints --query 'TargetGroups[0].TargetGroupArn' --output text)
TG_FN=$(aws elbv2 create-target-group --name "${PREFIX}-fn" --target-type lambda \
  --tags Key=pg-lab,Value=entrypoints --query 'TargetGroups[0].TargetGroupArn' --output text)
L_PUB=$(aws elbv2 create-listener --load-balancer-arn "$ALB_PUB" --protocol HTTP --port 80 \
  --default-actions Type=forward,TargetGroupArn="$TG_SVC" --query 'Listeners[0].ListenerArn' --output text)
aws elbv2 create-rule --listener-arn "$L_PUB" --priority 10 --conditions Field=path-pattern,Values='/fn*' \
  --actions Type=forward,TargetGroupArn="$TG_FN" >/dev/null
aws elbv2 create-listener --load-balancer-arn "$ALB_INT" --protocol HTTP --port 80 \
  --default-actions 'Type=fixed-response,FixedResponseConfig={StatusCode=200,ContentType=text/plain,MessageBody=internal}' >/dev/null
say "  load balancers: pub (internet-facing, :80 to an ECS service in a private subnet, /fn to a Lambda), int (internal)"

# ── ECS ─────────────────────────────────────────────────────────────────────
SLR_BEFORE=$(aws iam get-role --role-name AWSServiceRoleForECS >/dev/null 2>&1 && echo yes || echo no)
aws ecs create-cluster --cluster-name "$PREFIX" --tags key=pg-lab,value=entrypoints >/dev/null
TD=$(retry 12 aws ecs register-task-definition --family "$PREFIX" --network-mode awsvpc --requires-compatibilities FARGATE \
  --cpu 256 --memory 512 --task-role-arn "$TASK_ROLE" \
  --container-definitions '[{"name":"app","image":"public.ecr.aws/docker/library/busybox:latest","essential":true,"portMappings":[{"containerPort":80}]}]' \
  --query taskDefinition.taskDefinitionArn --output text)
service() { # service <name> <subnet> <sg> <ENABLED|DISABLED>
  retry 12 aws ecs create-service --cluster "$PREFIX" --service-name "$1" --task-definition "$TD" --desired-count 0 \
    --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[$2],securityGroups=[$3],assignPublicIp=$4}" >/dev/null
}
service web-public "$SN_PUBLIC" "$SG_WEB" ENABLED
service web-private "$SN_PRIVATE" "$SG_WEB" ENABLED
service web-noip "$SN_PUBLIC" "$SG_WEB" DISABLED
service icmp-only "$SN_PUBLIC" "$SG_ICMP" ENABLED
service acl-ssh "$SN_ACL" "$SG_SSHWEB" ENABLED
retry 12 aws ecs create-service --cluster "$PREFIX" --service-name behind-alb --task-definition "$TD" --desired-count 0 \
  --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[$SN_PRIVATE,$SN_PRIVATE_B],securityGroups=[$SG_APP],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$TG_SVC,containerName=app,containerPort=80" >/dev/null
say "  ECS services (desiredCount 0): web-public, web-private, web-noip, icmp-only, acl-ssh, behind-alb"

# ── Lambda ──────────────────────────────────────────────────────────────────
python3 - "$WORK/fn.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("index.py", "def handler(event, context):\n    return {'statusCode': 200, 'body': 'pg lab'}\n")
PY
for f in "${FUNCTIONS[@]}"; do
  retry 12 aws lambda create-function --function-name "${PREFIX}-${f}" --runtime python3.13 --handler index.handler \
    --role "$FN_ROLE" --zip-file "fileb://$WORK/fn.zip" --tags pg-lab=entrypoints >/dev/null
  aws lambda wait function-active-v2 --function-name "${PREFIX}-${f}"
  # Reserved concurrency 0: whatever the URL lets through, the function never runs.
  aws lambda put-function-concurrency --function-name "${PREFIX}-${f}" --reserved-concurrent-executions 0 >/dev/null
done
url_permission() { aws lambda add-permission --function-name "${PREFIX}-$1" --statement-id url --action lambda:InvokeFunctionUrl --principal '*' --function-url-auth-type NONE >/dev/null; }
invoke_permission() { aws lambda add-permission --function-name "${PREFIX}-$1" --statement-id invoke --action lambda:InvokeFunction --principal '*' --invoked-via-function-url >/dev/null; }
aws lambda create-function-url-config --function-name "${PREFIX}-open" --auth-type NONE >/dev/null
url_permission open
invoke_permission open
aws lambda create-function-url-config --function-name "${PREFIX}-urlonly" --auth-type NONE >/dev/null
url_permission urlonly
aws lambda create-function-url-config --function-name "${PREFIX}-iam" --auth-type AWS_IAM >/dev/null
FN_PRIVATE_ARN=$(aws lambda get-function --function-name "${PREFIX}-private" --query Configuration.FunctionArn --output text)
aws lambda add-permission --function-name "${PREFIX}-private" --statement-id elb --action lambda:InvokeFunction \
  --principal elasticloadbalancing.amazonaws.com --source-arn "$TG_FN" >/dev/null
retry 12 aws elbv2 register-targets --target-group-arn "$TG_FN" --targets Id="$FN_PRIVATE_ARN"
say "  functions: open (URL NONE, both grants AWS asks for), urlonly (URL NONE, the URL grant only),"
say "             iam (URL AWS_IAM), private (no URL); all at reserved concurrency 0"

# ── API Gateway ─────────────────────────────────────────────────────────────
FN_IAM_ARN=$(aws lambda get-function --function-name "${PREFIX}-iam" --query Configuration.FunctionArn --output text)
apigw_may_invoke() { # apigw_may_invoke <function> <statement id> <api id>
  aws lambda add-permission --function-name "${PREFIX}-$1" --statement-id "$2" --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT}:$3/*" >/dev/null
}
# An HTTP API: GET /open asks for nothing; GET /jwt wants a Google ID token for a client id
# no one can hold (Google generates them; nobody picks one). AWS checks that the issuer
# publishes an OpenID discovery document, so the issuer has to be a real one.
HTTP_API=$(aws apigatewayv2 create-api --name "${PREFIX}-http" --protocol-type HTTP --query ApiId --output text)
I_OPEN=$(aws apigatewayv2 create-integration --api-id "$HTTP_API" --integration-type AWS_PROXY --integration-uri "$FN_PRIVATE_ARN" \
  --payload-format-version 2.0 --query IntegrationId --output text)
I_JWT=$(aws apigatewayv2 create-integration --api-id "$HTTP_API" --integration-type AWS_PROXY --integration-uri "$FN_IAM_ARN" \
  --payload-format-version 2.0 --query IntegrationId --output text)
AUTH=$(aws apigatewayv2 create-authorizer --api-id "$HTTP_API" --authorizer-type JWT --name jwt \
  --identity-source '$request.header.Authorization' --jwt-configuration Audience=pg-lab-unissued.apps.googleusercontent.com,Issuer=https://accounts.google.com \
  --query AuthorizerId --output text)
aws apigatewayv2 create-route --api-id "$HTTP_API" --route-key 'GET /open' --target "integrations/$I_OPEN" >/dev/null
aws apigatewayv2 create-route --api-id "$HTTP_API" --route-key 'GET /jwt' --target "integrations/$I_JWT" \
  --authorization-type JWT --authorizer-id "$AUTH" >/dev/null
aws apigatewayv2 create-stage --api-id "$HTTP_API" --stage-name '$default' --auto-deploy >/dev/null
apigw_may_invoke private apigw-http "$HTTP_API"
apigw_may_invoke iam apigw-http "$HTTP_API"
# Two REST APIs, each with GET / asking for nothing into the private function; the second's
# policy lets everyone in, then denies everyone outside 192.0.2.0/24 - a documentation range.
rest_api() { # rest_api <name> [policy] -> "<id> <root resource id>"
  local id root
  if [ -n "${2:-}" ]; then
    id=$(aws apigateway create-rest-api --name "${PREFIX}-$1" --endpoint-configuration types=REGIONAL --policy "$2" --query id --output text)
  else
    id=$(aws apigateway create-rest-api --name "${PREFIX}-$1" --endpoint-configuration types=REGIONAL --query id --output text)
  fi
  root=$(aws apigateway get-resources --rest-api-id "$id" --query 'items[0].id' --output text)
  aws apigateway put-method --rest-api-id "$id" --resource-id "$root" --http-method GET --authorization-type NONE >/dev/null
  aws apigateway put-integration --rest-api-id "$id" --resource-id "$root" --http-method GET --type AWS_PROXY \
    --integration-http-method POST --uri "arn:aws:apigateway:${REGION}:lambda:path/2015-03-31/functions/${FN_PRIVATE_ARN}/invocations" >/dev/null
  # API Gateway throttles deployments (TooManyRequests), and an API left undeployed is
  # closed for the wrong reason - the check that policy or route is meant to settle would
  # pass without being made. So retry, and fail the lab rather than carry on: this runs in
  # $(...), where set -e does not reach, so the failure has to be returned.
  retry 6 aws apigateway create-deployment --rest-api-id "$id" --stage-name prod >/dev/null || return 1
  apigw_may_invoke private "apigw-$1" "$id"
  echo "$id"
}
OFFICE='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"NotIpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]}'
REST_OPEN=$(rest_api rest)
REST_OFFICE=$(rest_api office "$OFFICE")
say "  APIs: http (GET /open open, GET /jwt behind a JWT authorizer), rest (GET / open), office (denies outside 192.0.2.0/24)"

# ── S3 ──────────────────────────────────────────────────────────────────────
SUFFIX=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
BUCKETS=()
bucket() { # bucket <case> <statement JSON without Resource>...
  local name="${PREFIX}-${SUFFIX}-$1"
  aws s3api create-bucket --bucket "$name" --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
  aws s3api put-bucket-tagging --bucket "$name" --tagging 'TagSet=[{Key=pg-lab,Value=entrypoints}]'
  # Policies may be public; RestrictPublicBuckets keeps any stranger out all the same.
  aws s3api put-public-access-block --bucket "$name" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true
  local policy
  policy=$(python3 -c 'import json,sys; ss=[json.loads(a) for a in sys.argv[2:]]; [s.update(Resource=["arn:aws:s3:::"+sys.argv[1], "arn:aws:s3:::"+sys.argv[1]+"/*"] if s["Action"]=="s3:*" else "arn:aws:s3:::"+sys.argv[1]+"/*") for s in ss]; print(json.dumps({"Version":"2012-10-17","Statement":ss}))' "$name" "${@:2}")
  retry 12 aws s3api put-bucket-policy --bucket "$name" --policy "$policy"
  BUCKETS+=("$name")
}
GET='"Effect":"Allow","Principal":"*","Action":"s3:GetObject"'
bucket open     "{${GET},\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"true\"}}}"
bucket referer  "{${GET},\"Condition\":{\"StringLike\":{\"aws:Referer\":\"https://example.com/*\"}}}"
bucket vpcwild  "{${GET},\"Condition\":{\"StringLike\":{\"aws:SourceVpc\":\"vpc-*\"}}}"
bucket ipfixed  "{${GET},\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"192.0.2.0/24\"}}}"
bucket ipbroad  "{${GET},\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"0.0.0.0/1\"}}}"
bucket vpce     "{${GET},\"Condition\":{\"StringEquals\":{\"aws:SourceVpce\":\"vpce-0123456789abcdef0\"}}}"
bucket account  "{${GET},\"Condition\":{\"StringEquals\":{\"aws:PrincipalAccount\":\"${ACCOUNT}\"}}}"
bucket grantee  "{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"${GRANTEE}\"},\"Action\":\"s3:GetObject\"}"
bucket putonly  "{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\"}"
# The commonest policy there is: open, and "denied" to anyone not using TLS - which an attacker does.
bucket tlsdeny  "{${GET}}" "{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}"
say "  ${#BUCKETS[@]} empty buckets, each with one policy statement, all behind RestrictPublicBuckets"

say ""
say "  waiting for IAM and Lambda permissions to settle…"
sleep 15

# ── Referees ────────────────────────────────────────────────────────────────
python3 - "$WORK/buckets.json" "$ACCOUNT" "${BUCKETS[@]}" <<'PY'
import json, subprocess, sys
out, account, names = sys.argv[1], sys.argv[2], sys.argv[3:]
def aws(*a):
    return json.loads(subprocess.run(["aws", *a, "--output", "json"], check=True, capture_output=True, text=True).stdout)
buckets = []
for n in names:
    buckets.append({
        "name": n,
        "policy": aws("s3api", "get-bucket-policy", "--bucket", n)["Policy"],
        "bpa": aws("s3api", "get-public-access-block", "--bucket", n)["PublicAccessBlockConfiguration"],
        "aws_public": aws("s3api", "get-bucket-policy-status", "--bucket", n)["PolicyStatus"]["IsPublic"],
    })
json.dump({"account": account, "buckets": buckets}, open(out, "w"), indent=2)
PY
: >"$WORK/urls.txt"
for f in open urlonly iam; do
  url=$(aws lambda get-function-url-config --function-name "${PREFIX}-${f}" --query FunctionUrl --output text)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$url" || true)
  echo "${PREFIX}-${f} $code" >>"$WORK/urls.txt"
done

aws elbv2 wait load-balancer-available --load-balancer-arns "$ALB_PUB" "$ALB_INT"
: >"$WORK/lbs.txt"
for lb in pub int; do
  arn=$ALB_PUB; [ "$lb" = int ] && arn=$ALB_INT
  dns=$(aws elbv2 describe-load-balancers --load-balancer-arns "$arn" --query 'LoadBalancers[0].DNSName' --output text)
  code=000
  # A new name takes a minute or two to resolve; an internal one resolves to private
  # addresses this machine cannot reach, and never answers.
  for _ in $(seq 1 24); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://$dns/" || true)
    [ "$code" != "000" ] && break
    [ "$lb" = int ] && [ "$(dig +short "$dns" | head -1)" != "" ] && break
    sleep 5
  done
  echo "$lb $code" >>"$WORK/lbs.txt"
done

# Each route, asked without credentials. A new stage can answer 404 for a few seconds.
: >"$WORK/apis.txt"
api_code() { # api_code <label> <url>
  local code=000
  for _ in $(seq 1 12); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$2" || true)
    case "$code" in 000|404) sleep 5 ;; *) break ;; esac
  done
  echo "$1 $code" >>"$WORK/apis.txt"
}
api_code http-open "https://${HTTP_API}.execute-api.${REGION}.amazonaws.com/open"
api_code http-jwt "https://${HTTP_API}.execute-api.${REGION}.amazonaws.com/jwt"
api_code rest-open "https://${REST_OPEN}.execute-api.${REGION}.amazonaws.com/prod/"
api_code rest-office "https://${REST_OFFICE}.execute-api.${REGION}.amazonaws.com/prod/"

# ── The engine ──────────────────────────────────────────────────────────────
collect() {
  (cd "$ROOT/backend" && CGO_ENABLED=0 go run ./cmd/perspectivegraph awscollect -region "$REGION" \
    -role "arn:aws:iam::${ACCOUNT}:role/${READONLY_ROLE}" -json) >"$1" 2>"$1.err" || { cat "$1.err" >&2; return 1; }
  if grep -q "partial collect" "$1.err"; then cat "$1.err" >&2; fi
}
say ""
say "── the engine reads the account as ${READONLY_ROLE} (SecurityAudit only) ──"
collect "$WORK/events.json"

# Retraction: take the open function's URL away, keep its policy, read again.
aws lambda delete-function-url-config --function-name "${PREFIX}-open"
sleep 5
collect "$WORK/events-after.json"

status=0
python3 - "$WORK" "$PREFIX" "$GH_OPEN" "$WORK/rows.jsonl" <<'PY' || status=$?
import json, sys
work, prefix, gh_open, rows_path = sys.argv[1:5]
def load(p):
    nodes, edges = {}, []
    for ev in json.load(open(p)):
        for n in ev.get("nodes") or []:
            nodes.setdefault(n["id"], {"label": n["label"], "name": n["name"], "props": {}})["props"].update(n.get("properties") or {})
        edges += ev.get("edges") or []
    return nodes, edges
nodes, edges = load(f"{work}/events.json")
after, _ = load(f"{work}/events-after.json")
by_name = lambda ns, label, name: next((n for n in ns.values() if n["label"] == label and n["name"] == name), None)
rows, bad = [], 0
def check(what, expected, got, why):
    global bad
    ok = expected == got
    bad += not ok
    rows.append((("PASS" if ok else "FAIL"), what, str(expected), str(got), why))

# record writes a check AWS answered to the rows the dashboard's record is made from. Checks
# against the lab's own construction - ports, edges, routing rules - are not AWS's answers,
# and stay out of it.
def record(case, question, referee, aws_says, engine_says, ok):
    with open(rows_path, "a") as f:
        f.write(json.dumps({"case": case, "question": question, "referee": referee, "aws": aws_says,
                            "engine": engine_says, "verdict": "agree" if ok else "disagree"}) + "\n")

def exposed(n):
    p = n["props"]
    return bool(p.get("network_exposed", p.get("internet_exposed", False)))

# ECS services and ports
ecs = {
    "web-public":  (True,  "tcp/443", "", "public address, routed subnet, 443 open"),
    "web-private": (False, "", "",        "no route to the internet gateway"),
    "web-noip":    (False, "", "",        "no public address assigned"),
    "icmp-only":   (False, "", "",        "only ICMP open: nothing to talk to"),
    "acl-ssh":     (True,  "tcp/443", "", "SG opens 22 and 443, the NACL lets in 443 only"),
}
for svc, (exp, ports, mgmt, why) in ecs.items():
    n = by_name(nodes, "Container", svc)
    if n is None:
        check(f"ECS {svc}", "read", "missing", why); continue
    check(f"ECS {svc} exposed", exp, exposed(n), why)
    if exp:
        check(f"ECS {svc} ports", ports, n["props"].get("exposed_ports", ""), why)
        check(f"ECS {svc} management ports", mgmt or "none", n["props"].get("exposed_management_ports", "") or "none", why)
task = next((i for i, n in nodes.items() if n["label"] == "IAM_Role" and n["name"] == f"{prefix}-task"), None)
web = next((i for i, n in nodes.items() if n["label"] == "Container" and n["name"] == "web-public"), None)
check("ECS web-public -> task role", True, any(e["type"] == "ASSUMES" and e["from"] == web and e["to"] == task for e in edges), "the task role every container can fetch")

# Lambda, against what the function URL actually answered
codes = dict(l.split() for l in open(f"{work}/urls.txt"))
for fn in ("open", "urlonly", "iam", "private"):
    name = f"{prefix}-{fn}"
    n = by_name(nodes, "Function", name)
    if n is None:
        check(f"Lambda {fn}", "read", "missing", ""); continue
    code = codes.get(name)
    aws_open = code is not None and code != "403"
    why = f"unauthenticated request answered {code}" if code else "no function URL"
    check(f"Lambda {fn} exposed (AWS: {'open' if aws_open else 'closed'})", aws_open, exposed(n), why + "; " + n["props"].get("exposure", ""))
    if code:
        record(f"function {fn}", "Does a stranger get past the function URL's authorization?",
               "an unauthenticated request to the function URL", f"{code} ({'let through' if aws_open else 'refused'})",
               "open" if exposed(n) else "closed", aws_open == exposed(n))
fn_role = next((i for i, n in nodes.items() if n["label"] == "IAM_Role" and n["name"] == f"{prefix}-fn"), None)
fn_open = next((i for i, n in nodes.items() if n["label"] == "Function" and n["name"] == f"{prefix}-open"), None)
check("Lambda open -> execution role", True, any(e["type"] == "ASSUMES" and e["from"] == fn_open and e["to"] == fn_role for e in edges), "")
n = by_name(after, "Function", f"{prefix}-open")
check("Lambda open, URL deleted: retracted", False, exposed(n) if n else "missing", "the policy stays, the URL is gone" + ("; " + n["props"].get("exposure", "") if n else ""))

# Load balancers, against whether an HTTP request to each DNS name got an answer
lbcodes = dict(l.split() for l in open(f"{work}/lbs.txt"))
for lb in ("pub", "int"):
    n = by_name(nodes, "LoadBalancer", f"{prefix}-{lb}")
    if n is None:
        check(f"LB {lb}", "read", "missing", ""); continue
    code = lbcodes.get(lb, "000")
    answered = code != "000"
    check(f"LB {lb} exposed (AWS: {'answers' if answered else 'silent'})", answered, exposed(n),
          f"an HTTP request to its DNS name answered {code}; " + n["props"].get("net_reachability", ""))
    record(f"load balancer {'internet-facing' if lb == 'pub' else 'internal'}", "Does the internet reach this load balancer?",
           "an HTTP request to its DNS name", f"answered {code}" if answered else "no answer",
           "exposed" if exposed(n) else "not exposed", answered == exposed(n))
    if answered:
        check(f"LB {lb} ports", "tcp/80", n["props"].get("exposed_ports", ""), "the listener serves 80, the group admits 80")
pub = next((i for i, n in nodes.items() if n["label"] == "LoadBalancer" and n["name"] == f"{prefix}-pub"), None)
behind = next((i for i, n in nodes.items() if n["label"] == "Container" and n["name"] == "behind-alb"), None)
fn_private = next((i for i, n in nodes.items() if n["label"] == "Function" and n["name"] == f"{prefix}-private"), None)
routes_to = {(e["from"], e["to"]) for e in edges if e["type"] == "ROUTES_TO"}
check("LB pub -> ECS behind-alb", True, (pub, behind) in routes_to, "through the service's target group, with no task running")
check("LB pub -> Lambda private", True, (pub, fn_private) in routes_to, "a lambda target group")
check("ECS behind-alb exposed", False, exposed(nodes[behind]) if behind else "missing", "private subnets, no public address: only the load balancer reaches it")

# API Gateway, against what each route answered a stranger
apicodes = dict(l.split() for l in open(f"{work}/apis.txt"))
answers = lambda code: code not in ("401", "403", "000", "404")
routes_to = {(e["from"], e["to"]) for e in edges if e["type"] == "ROUTES_TO"}
api = lambda name: next(((i, n) for i, n in nodes.items() if n["label"] == "API" and n["name"] == f"{prefix}-{name}"), (None, None))
fn_iam = next((i for i, n in nodes.items() if n["label"] == "Function" and n["name"] == f"{prefix}-iam"), None)
check("AWS: the JWT route refuses a stranger", True, apicodes.get("http-jwt") in ("401", "403"), f"answered {apicodes.get('http-jwt')}")
for name, label in (("http", "http-open"), ("rest", "rest-open"), ("office", "rest-office")):
    i, n = api(name)
    if n is None:
        check(f"API {name}", "read", "missing", ""); continue
    code = apicodes.get(label, "000")
    check(f"API {name} exposed (AWS: {'answers' if answers(code) else 'refuses'})", answers(code), exposed(n),
          f"an unauthenticated request answered {code}; " + n["props"].get("exposure", ""))
    record(f"API {name}", "Does this API answer a stranger?", "an unauthenticated request to its open route",
           code, "an entry point" if exposed(n) else "no way in", answers(code) == exposed(n))
http_id, http = api("http")
rest_id, _ = api("rest")
# Closed for the right reason: an API left undeployed is closed too, and would pass the
# check above without its policy ever being read.
_, office = api("office")
if office:
    check("API office closed by its policy", True, "resource policy" in office["props"].get("exposure", ""),
          office["props"].get("exposure", ""))
if http:
    check("API http open routes", "GET /open", http["props"].get("open_routes", ""), "GET /jwt sits behind the authorizer")
check("API http -> Lambda private", True, (http_id, fn_private) in routes_to, "the open route's integration")
check("API http -> Lambda iam", False, (http_id, fn_iam) in routes_to, "only the JWT route reaches it")
jwt = apicodes.get("http-jwt", "000")
record("API http, route behind a JWT authorizer", "Does a stranger get through the route behind the authorizer?",
       "an unauthenticated request to the route", jwt,
       "a route to its function" if (http_id, fn_iam) in routes_to else "no route",
       (jwt in ("401", "403")) == ((http_id, fn_iam) not in routes_to))
check("API rest -> Lambda private", True, (rest_id, fn_private) in routes_to, "read from the method's integration URI")

# GitHub OIDC
idps = [n for n in nodes.values() if n["label"] == "IdentityProvider" and n["props"].get("oidc_issuer") == "token.actions.githubusercontent.com"]
pinned = [n for n in idps if "pg-lab-example/demo" in n["props"].get("oidc_subjects", "")]
check("GitHub pinned trust drawn", True, bool(pinned), "repo:pg-lab-example/demo:*")
check("GitHub pinned trust is no entry point", False, any(n["props"].get("internet_exposed") for n in pinned), "pinned to one repository")
if gh_open == "accepted":
    check("GitHub open trust (AWS accepted it) is an entry point", True, any(n["props"].get("internet_exposed") for n in idps), "any repository")
else:
    rows.append(("INFO", "GitHub open trust", "-", "-", "AWS refused to create it, as the docs say"))

w = max(len(r[1]) for r in rows)
for r in rows:
    print(f"  {r[0]:4}  {r[1]:{w}}  expected {r[2]:<8} engine {r[3]:<8}  {r[4]}")
sys.exit(1 if bad else 0)
PY

say ""
say "── S3: the custodian collector against GetBucketPolicyStatus ──"
(cd "$ROOT/backend" && PG_LAB_BUCKETS="$WORK/buckets.json" PG_LAB_ROWS="$WORK/rows.jsonl" go test ./internal/ingestion/custodian/ \
  -run TestBucketVerdictsAgreeWithAWS -count=1 -v) >"$WORK/s3.out" 2>&1 || status=1
grep -E 'lab_test.go|^(--- |ok|FAIL)' "$WORK/s3.out" | sed 's/^ *lab_test.go:[0-9]*: /  /' >&2
# The record the dashboard's Accuracy page shows: the checks AWS answered, disagreements included.
if [ -s "$WORK/rows.jsonl" ]; then
  python3 "$ROOT/scripts/lab-record.py" --lab entrypoints-lab-aws \
    --title "Entry points: bucket policies, function URLs, load balancers, API routes" \
    --command "make entrypoints-lab-aws" --region "$REGION" --cost "a few cents" --rows "$WORK/rows.jsonl"
fi

say ""
say "─────────────────────────────────────────────────────────────"
if [ "$status" -eq 0 ]; then
  say "  PASS: on a real account, the engine agrees with AWS on every bucket policy and"
  say "  function URL, and exposes, suppresses and retracts as the routing rules say."
else
  say "  FAIL: the engine and AWS (or the routing rules) disagree above. Each FAIL is a"
  say "  false positive or a miss, found on real infrastructure."
fi
if [ "$KEEP" = "1" ]; then
  say "  KEEP=1: the lab is still up. Tear it down with: ./scripts/entrypoints-lab-aws.sh --teardown"
fi
exit "$status"
