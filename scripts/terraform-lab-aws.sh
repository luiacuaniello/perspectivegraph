#!/usr/bin/env bash
#
# terraform-lab-aws.sh - the merge gate on Terraform plans, checked on a REAL AWS account,
# with AWS as the referee.
#
# The gate reads a plan before it is applied and says whether it opens a route from the
# internet to something that matters. This lab applies each plan after the gate has judged
# it, and asks AWS what actually happened: a TCP connection from the internet to the
# instance's port 8080 says whether the internet reaches it, and IAM's policy simulator
# says whether the role the instance holds can make itself administrator.
#
# The stack, applied with Terraform: a VPC with a public subnet routed to an internet
# gateway, behind a network ACL; a t3.micro with a public address, serving an empty
# directory on 8080, IMDSv2 required; its role, allowed iam:AttachRolePolicy on itself;
# its own security group, which lets 8080 in only from 10.0.0.0/8, and a second one with
# no rules, which a second configuration manages the rules of. The cases, each a plan:
#
#   open          the instance's group opens 8080 to the internet     -> blocked
#   acl           the network ACL denies 8080 in front of it          -> clean
#   acl-removed   the plan deletes that deny, a rule resource, which
#                 the ACL's own attribute still shows until apply     -> blocked
#   unchanged     a plan that changes nothing                         -> clean
#   shared        the second configuration opens 8080 on the shared
#                 group: the instance is not in that plan at all      -> unknown alone,
#                                                                        blocked with the
#                                                                        account read
#
# The gate runs on each plan twice: alone, and with the account read live (-aws-region) as
# PerspectiveGraphReadOnly, whose only policy is SecurityAudit. The second is the verdict
# the referee grades; the first must agree with it, except on the shared group, where it
# must say it cannot tell (unknown). Then the plan is applied and the referee asked.
#
# Cost: a few cents at most - the t3.micro and its public IPv4 address for the ten or so
# minutes the lab is up; everything else is free. The instance serves an empty directory
# and nothing else. Terraform's state is kept in STATE_DIR, so --teardown can destroy a
# lab left up; an EXIT trap destroys it otherwise.
#
#   PROFILE=pg-admin REGION=eu-north-1 ./scripts/terraform-lab-aws.sh
#   KEEP=1 ... ./scripts/terraform-lab-aws.sh    # leave the lab up to inspect it
#   ./scripts/terraform-lab-aws.sh --teardown    # destroy a leaked lab

set -euo pipefail

PROFILE="${PROFILE:-pg-admin}"
REGION="${REGION:-eu-north-1}"
PREFIX="${PREFIX:-pg-tf-lab}"
KEEP="${KEEP:-0}"
READONLY_ROLE="${READONLY_ROLE:-PerspectiveGraphReadOnly}"
STATE_DIR="${STATE_DIR:-${HOME}/.cache/perspectivegraph/terraform-lab}"

export AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" AWS_PAGER=""
export TF_IN_AUTOMATION=1 TF_INPUT=0
say() { printf '%s\n' "$*" >&2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STACK="$STATE_DIR/stack"
OTHER="$STATE_DIR/other"
WORK=""

command -v terraform >/dev/null || { say "terraform is not installed: the lab applies plans with it"; exit 2; }
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# ── The configurations ──────────────────────────────────────────────────────
write_configs() {
  mkdir -p "$STACK" "$OTHER"
  cat >"$STACK/main.tf" <<EOF
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" {
  region = "${REGION}"
  default_tags {
    tags = { pg-lab = "terraform" }
  }
}

variable "open" {
  type    = bool
  default = false
}
variable "acl_deny" {
  type    = bool
  default = false
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
}

resource "aws_vpc" "lab" {
  cidr_block = "10.42.0.0/16"
  tags       = { Name = "${PREFIX}" }
}
resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
}
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.1.0/24"
  map_public_ip_on_launch = true
}
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
# Its entries are rule resources, so deleting one leaves the ACL's own attribute showing it
# until apply: the case a reader of plans has to get right.
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.lab.id
  subnet_ids = [aws_subnet.public.id]
}
resource "aws_network_acl_rule" "in_all" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_network_acl_rule" "out_all" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_network_acl_rule" "deny_web" {
  count          = var.acl_deny ? 1 : 0
  network_acl_id = aws_network_acl.public.id
  rule_number    = 90
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 8080
  to_port        = 8080
}

resource "aws_security_group" "web" {
  name   = "${PREFIX}-web"
  vpc_id = aws_vpc.lab.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_vpc_security_group_ingress_rule" "private" {
  security_group_id = aws_security_group.web.id
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = "10.0.0.0/8"
}
resource "aws_vpc_security_group_ingress_rule" "public" {
  count             = var.open ? 1 : 0
  security_group_id = aws_security_group.web.id
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = "0.0.0.0/0"
}
# Its rules are another configuration's.
resource "aws_security_group" "shared" {
  name   = "${PREFIX}-shared"
  vpc_id = aws_vpc.lab.id
  lifecycle {
    ignore_changes = [ingress]
  }
}

resource "aws_iam_role" "web" {
  name = "${PREFIX}-web"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "self_attach" {
  name = "self-attach"
  role = aws_iam_role.web.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "iam:AttachRolePolicy", Resource = aws_iam_role.web.arn }]
  })
}
resource "aws_iam_instance_profile" "web" {
  name = "${PREFIX}-web"
  role = aws_iam_role.web.name
}

resource "aws_instance" "web" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id, aws_security_group.shared.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
  metadata_options {
    http_tokens = "required"
  }
  user_data = <<-UD
    #!/bin/bash
    mkdir -p /srv/empty
    nohup python3 -m http.server 8080 --directory /srv/empty >/dev/null 2>&1 &
  UD
  tags = { Name = "${PREFIX}-web" }
}

output "public_ip" {
  value = aws_instance.web.public_ip
}
output "shared_sg" {
  value = aws_security_group.shared.id
}
output "role_arn" {
  value = aws_iam_role.web.arn
}
EOF
  cat >"$OTHER/main.tf" <<EOF
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" {
  region = "${REGION}"
  default_tags {
    tags = { pg-lab = "terraform" }
  }
}

variable "shared_sg" {
  type = string
}
variable "open" {
  type    = bool
  default = false
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  count             = var.open ? 1 : 0
  security_group_id = var.shared_sg
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = "0.0.0.0/0"
}
EOF
}

tf() { # tf <dir> <args…>
  local dir="$1"; shift
  terraform -chdir="$dir" "$@"
}

# ── Teardown ────────────────────────────────────────────────────────────────
# The second configuration first: its rule lives on the stack's group.
teardown() {
  set +e
  say ""
  say "── tearing down ──────────────────────────────────────────────"
  if [ -f "$OTHER/terraform.tfstate" ]; then
    tf "$OTHER" destroy -auto-approve -var "shared_sg=$(tf "$STACK" output -raw shared_sg 2>/dev/null || echo sg-none)" >"$STATE_DIR/destroy-other.log" 2>&1 &&
      say "  destroyed the second configuration's rule" || say "  could not destroy the second configuration: see $STATE_DIR/destroy-other.log"
  fi
  if [ -f "$STACK/terraform.tfstate" ]; then
    if tf "$STACK" destroy -auto-approve >"$STATE_DIR/destroy-stack.log" 2>&1; then
      say "  destroyed the stack"
    else
      say "  could not destroy the stack: see $STATE_DIR/destroy-stack.log"
    fi
  fi
  left=$(aws resourcegroupstaggingapi get-resources --tag-filters Key=pg-lab,Values=terraform \
    --query 'ResourceTagMappingList[].ResourceARN' --output text 2>/dev/null)
  instances=$(aws ec2 describe-instances --filters Name=tag:pg-lab,Values=terraform \
    Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[].Instances[].InstanceId' --output text)
  roles=$(aws iam list-roles --query "Roles[?starts_with(RoleName, '${PREFIX}-')].RoleName" --output text)
  if [ -z "$instances" ] && [ -z "$roles" ]; then
    say "  verified: no instance and no role of the lab is left"
  else
    say "  LEFT BEHIND: instances [$instances] roles [$roles] - destroy them by hand"
  fi
  [ -n "$left" ] && say "  still tagged pg-lab=terraform (the tagging API lags deletions by minutes): $left"
  [ -n "$WORK" ] && rm -rf "$WORK"
  set -e
}

if [ "${1:-}" = "--teardown" ]; then
  teardown
  exit 0
fi
if [ -f "$STACK/terraform.tfstate" ] && [ -n "$(tf "$STACK" state list 2>/dev/null)" ]; then
  say "A lab is already up (state in $STACK). Destroy it first: ./scripts/terraform-lab-aws.sh --teardown"
  exit 2
fi
aws iam get-role --role-name "$READONLY_ROLE" >/dev/null 2>&1 ||
  { say "The read-only role $READONLY_ROLE does not exist: the gate reads the account through it (SecurityAudit)."; exit 2; }

WORK=$(mktemp -d)
if [ "$KEEP" != "1" ]; then
  trap teardown EXIT
fi
write_configs

say "── building the gate ─────────────────────────────────────────"
(cd "$ROOT/backend" && CGO_ENABLED=0 go build -o "$WORK/pg" ./cmd/perspectivegraph)

say "── applying the stack in ${REGION} ───────────────────────────"
tf "$STACK" init -no-color >"$WORK/init.log" 2>&1 || { cat "$WORK/init.log" >&2; exit 1; }
tf "$OTHER" init -no-color >"$WORK/init-other.log" 2>&1 || { cat "$WORK/init-other.log" >&2; exit 1; }
tf "$STACK" apply -auto-approve -no-color >"$WORK/apply.log" 2>&1 || { tail -30 "$WORK/apply.log" >&2; exit 1; }
IP=$(tf "$STACK" output -raw public_ip)
SHARED=$(tf "$STACK" output -raw shared_sg)
ROLE_ARN=$(tf "$STACK" output -raw role_arn)
say "  web: a t3.micro at a public address, serving 8080, its groups closed to the internet"

# ── Gate, apply, referee ────────────────────────────────────────────────────
# gate <plan.json> <alone|live>: the gate's verdict - clean, blocked or unknown - and, after
# a tab, its routes or what it could not see.
gate() {
  local args=(gate -local -source terraform -report "$1" -slug "pg/terraform-lab" -sha "$(python3 -c 'import secrets; print(secrets.token_hex(20))')" -json)
  if [ "$2" = "live" ]; then
    args+=(-aws-region "$REGION" -aws-role "arn:aws:iam::${ACCOUNT}:role/${READONLY_ROLE}")
  fi
  local code=0
  "$WORK/pg" "${args[@]}" >"$WORK/gate.json" 2>"$WORK/gate.err" || code=$?
  python3 - "$WORK/gate.json" "$code" <<'PY'
import json, sys
path, code = sys.argv[1], int(sys.argv[2])
verdict = {0: "clean", 1: "blocked", 2: "unknown"}.get(code, "error")
try:
    v = json.load(open(path))
except ValueError:
    print(verdict + "\t" + "the gate wrote no verdict")
    sys.exit()
routes = ["; ".join(" -> ".join(n["name"] for n in p["nodes"]) for p in v.get("paths") or [])]
detail = routes[0] if routes[0] else v.get("incomplete", "")
print(verdict + "\t" + detail)
PY
}

# probe: does a TCP connection from here, on the internet, reach the instance's 8080?
probe() {
  if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(5); sys.exit(0 if s.connect_ex((sys.argv[1], 8080)) == 0 else 1)' "$IP"; then
    echo open
  else
    echo closed
  fi
}

# reached: what the internet reaches once a change has settled. The first time, the server
# may still be starting on a new instance: wait for it, up to three minutes. After that, a
# group or ACL change takes seconds to reach the network: wait, and take the last of a few
# probes.
# It runs in a subshell, $(reached): whether the server has been seen up is kept in a file.
reached() {
  local r=closed
  if [ ! -f "$WORK/server-up" ]; then
    for _ in $(seq 1 36); do
      r=$(probe)
      [ "$r" = "open" ] && { touch "$WORK/server-up"; break; }
      sleep 5
    done
    echo "$r"
    return
  fi
  sleep 15
  for _ in 1 2 3 4; do
    r=$(probe)
    sleep 5
  done
  echo "$r"
}

status=0
: >"$WORK/rows.jsonl"

# check <case> <question> <dir> <expected alone> <expected live> <tf args…>
check() {
  local case="$1" question="$2" dir="$3" want_alone="$4" want_live="$5"; shift 5
  tf "$dir" plan -no-color -out "$WORK/$case.bin" "$@" >"$WORK/$case.plan.log" 2>&1 || { tail -20 "$WORK/$case.plan.log" >&2; status=1; return; }
  tf "$dir" show -json "$WORK/$case.bin" >"$WORK/$case.json"
  local alone live
  alone=$(gate "$WORK/$case.json" alone)
  live=$(gate "$WORK/$case.json" live)
  tf "$dir" apply -auto-approve -no-color "$WORK/$case.bin" >"$WORK/$case.apply.log" 2>&1 || { tail -20 "$WORK/$case.apply.log" >&2; status=1; return; }
  local aws_says
  aws_says=$(reached)
  python3 - "$WORK/rows.jsonl" "$case" "$question" "$aws_says" "$alone" "$live" "$want_alone" "$want_live" <<'PY' || status=1
import json, sys
rows, case, question, aws, alone, live, want_alone, want_live = sys.argv[1:9]
alone_v, _, alone_d = alone.partition("\t")
live_v, _, live_d = live.partition("\t")
# The referee grades the verdict made with the account read: a plan that opens a route is
# one after which the internet reaches the instance; one that opens none, one after which
# it does not - or whose route was already open.
agrees = (live_v == "blocked") == (aws == "open")
row = {"case": case, "question": question,
       "referee": "the plan applied, then a TCP connection from the internet to the instance's port 8080",
       "aws": "reached" if aws == "open" else "not reached",
       "engine": live_v + (": " + live_d if live_v == "blocked" and live_d else ""),
       "verdict": "agree" if agrees else "disagree"}
if live_v != want_live or alone_v != want_alone:
    row["note"] = "expected %s alone and %s with the account read" % (want_alone, want_live)
with open(rows, "a") as f:
    f.write(json.dumps(row) + "\n")
ok = agrees and alone_v == want_alone and live_v == want_live
mark = "PASS" if ok else "FAIL"
print("  %s  %-12s alone: %-8s with the account: %-8s internet: %s" % (mark, case, alone_v, live_v, aws), file=sys.stderr)
for label, v, d in (("alone", alone_v, alone_d), ("live", live_v, live_d)):
    if d:
        print("        %s: %s" % (label, d[:220]), file=sys.stderr)
sys.exit(0 if ok else 1)
PY
}

say ""
say "── each plan: the gate, then apply, then the internet ───────"
# The first case opens the instance, which also tells the referee the server is up.
check open "Does a plan that opens 8080 in the instance's security group open a way in?" "$STACK" blocked blocked -var open=true
check acl "Does a network ACL that denies 8080 keep the internet out, the group still open?" "$STACK" clean clean -var open=true -var acl_deny=true
check acl-removed "Does a plan that deletes that deny - still in the ACL's own attribute - open a way in?" "$STACK" blocked blocked -var open=true
tf "$STACK" apply -auto-approve -no-color >"$WORK/close.log" 2>&1 || { tail -20 "$WORK/close.log" >&2; status=1; }
check unchanged "Does a plan that changes nothing open a way in?" "$STACK" clean clean
check shared "Does a rule another configuration adds to a group the instance shares open a way in?" "$OTHER" unknown blocked \
  -var "shared_sg=$SHARED" -var open=true

# The role: IAM's own simulator on the step the routes end with.
say ""
say "── the role, against IAM's policy simulator ──────────────────"
decision=$(aws iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" --action-names iam:AttachRolePolicy \
  --resource-arns "$ROLE_ARN" --query 'EvaluationResults[0].EvalDecision' --output text)
python3 - "$WORK/rows.jsonl" "$decision" <<'PY' || status=1
import json, sys
rows, decision = sys.argv[1:3]
engine = "can make itself administrator"
agrees = decision == "allowed"
with open(rows, "a") as f:
    f.write(json.dumps({"case": "role", "question": "Can the instance's role attach a policy to itself - make itself administrator?",
        "referee": "IAM's policy simulator", "aws": decision, "engine": engine, "verdict": "agree" if agrees else "disagree"}) + "\n")
print("  %s  role         simulator: %s; the routes end at account-admin" % ("PASS" if agrees else "FAIL", decision), file=sys.stderr)
sys.exit(0 if agrees else 1)
PY

python3 "$ROOT/scripts/lab-record.py" --lab terraform-lab-aws \
  --title "Terraform plans, judged before apply and checked after it" \
  --command "make terraform-lab-aws" --region "$REGION" --cost "a few cents" --rows "$WORK/rows.jsonl"

say ""
say "─────────────────────────────────────────────────────────────"
if [ "$status" -eq 0 ]; then
  say "  PASS: on a real account, every plan the gate blocked opened a way in once applied,"
  say "  every plan it passed opened none, and the plan that reaches beyond its configuration"
  say "  was unknown alone and blocked with the account read."
else
  say "  FAIL: the gate and AWS disagree above, or a plan alone was not what it should be."
fi
if [ "$KEEP" = "1" ]; then
  say "  KEEP=1: the lab is still up. Tear it down with: ./scripts/terraform-lab-aws.sh --teardown"
fi
exit "$status"
