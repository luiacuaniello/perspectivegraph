# Onboarding runbook

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Pointing it at your own environment, source by source, until the first path appears.

PerspectiveGraph does **not** scan your infrastructure - it *correlates* the
output of the scanners you already run. There are no agents and nothing pulls:
your CI/cron runs the tools and **POSTs** their reports to the ingest webhook.
This runbook is the minimum a tester needs to light up a real attack path.

Set these once for every snippet below:

```bash
export INGEST_URL=http://your-host:8081     # ingestion webhook
export API_URL=http://your-host:8080        # GraphQL / dashboard BFF
export SLUG=acme/payments-api               # forge "owner/repo" (for PR comments)
```

---

## 0. Prerequisites

- The stack is up. Quickest path: **`make up-full`** runs everything in
  containers (infra + backend + dashboard on `:3000`). For the host dev loop use
  `make up` (just **Postgres+AGE** + **NATS**) then `make run-backend`. OpenSearch
  and `THREATINTEL=on` are optional. With `make up-full`, `INGEST_URL` is
  `http://localhost:8081` and `API_URL` is `http://localhost:8080`.
- Network: the tester's CI/cron can reach `INGEST_URL`. ⚠️ **The ingest and API
  endpoints have no authentication in this MVP** - keep them on an isolated
  network or behind an authenticating reverse proxy. Single-tenant.
- You can run **Trivy, Semgrep, Cloud Custodian, Falco** against the target, and
  add one **CI step** for build provenance.
- You can **tag** your sensitive data stores (this is what makes them targets -
  see §3).

Health check first:

```bash
curl -s $INGEST_URL/healthz   # → ok
curl -s $API_URL/healthz      # → ok
```

### Authentication

If the backend runs with auth enabled (it should, outside a laptop), every
request must be signed/authorized - otherwise you get `401`.

- **Ingest** (`INGEST_HMAC_SECRET` set): sign the request with HMAC-SHA256 (v2) and
  send the signature with the time you signed it. The signed text is five lines -
  `v2`, the unix time, the method, the path, the query, then the hex SHA-256 of the body -
  with the query's parameters **sorted by name** and URL-encoded as sent. A reusable
  helper:

  ```bash
  export INGEST_HMAC_SECRET=...   # the shared secret
  pgsign2() {  # usage: pgsign2 <path> <sorted-query> <file>  → sets PG_TS and PG_SIG
    PG_TS=$(date +%s)
    local sum; sum=$(openssl dgst -sha256 -hex < "$3" | sed 's/^.*= //')
    PG_SIG=v2=$(printf 'v2\n%s\nPOST\n%s\n%s\n%s' "$PG_TS" "$1" "$2" "$sum" |
      openssl dgst -sha256 -hmac "$INGEST_HMAC_SECRET" -hex | sed 's/^.*= //')
  }
  q='pr=42&sha=deadbeef&slug=acme%2Fpayments-api'   # parameters sorted by name
  pgsign2 /ingest/trivy "$q" report.json
  curl -sS -X POST "http://localhost:8081/ingest/trivy?$q" -H 'Content-Type: application/json' \
    -H "X-PerspectiveGraph-Timestamp: $PG_TS" -H "X-PerspectiveGraph-Signature-V2: $PG_SIG" \
    --data-binary @report.json
  ```

  Each signature is accepted once, within five minutes of its timestamp - sign every
  request afresh. The v1 form (`X-PerspectiveGraph-Signature: sha256=` + the HMAC of the
  body alone) is still accepted unless `INGEST_HMAC_ACCEPT_V1=false`; the `gate`
  subcommand, the GitHub Action and the Postman collection send both.

- **API** (`API_TOKENS` set): send `Authorization: Bearer <viewer-token>` on
  every GraphQL request. The in-browser playground is disabled when auth is on.
  `GET /auth/me` with the same header shows what the token resolved to - the quickest way
  to tell a wrong token (401) from a role that is too low (`"canWrite": false`).

- **Multi-tenant** (`INGEST_HMAC_SECRETS` / token `:tenant` suffix): add
  `-H "X-Tenant: <your-tenant>"` to ingest requests and sign with *that tenant's*
  secret; the API token's tenant scopes what you can read. Each tenant's data is
  fully isolated in its own graph.

- **Audit-of-views** (`AUDIT_LOG_PATH` set): the tool is a map of how to breach
  the org, so set this in production - it tamper-evidently records who *viewed*
  the attack paths/graph (with the path ids seen) and who *exported* the map, not
  just who changed it. Check integrity with `perspectivegraph verify-audit <path>`.

The snippets below show the unsigned, single-tenant form for readability; add the
signature / bearer / `X-Tenant` headers when auth and tenancy are enabled.

---

## 1. The order that builds a correct graph

Feed these sources. Order doesn't strictly matter (edges whose endpoints haven't
arrived yet are retried), but this is the logical flow:

| # | Source | Endpoint | Gives the graph |
|---|--------|----------|-----------------|
| 1 | Cloud Custodian | `POST /ingest/custodian` | cloud topology + IAM + the `internet_exposed`/`crown_jewel` markers |
| 2 | Trivy | `POST /ingest/trivy` | images → libraries → CVEs |
| 3 | CI build provenance | `POST /ingest/build` | the **image ↔ repository** link (`BUILT_FROM`) |
| 4 | Semgrep | `POST /ingest/semgrep` | repository → code weaknesses / secrets |
| 5 | Falco | `POST /ingest/falco` | runtime confirmation on containers |
| 6 | Kubernetes dump | `POST /ingest/k8s` | **exposure topology**: Ingress→Service→Pod→SA→Role |
| 7 | Cloud network | `POST /ingest/cloudnet` | **reachability**: internet-facing SGs, SG-to-SG, VPC peering |
| 8 | IAM authorization | `POST /ingest/iam` | **privilege escalation**: `CAN_ESCALATE_TO` edges to account-admin, public-trust roles |
| 9 | EKS access | `POST /ingest/eks` | **cluster ↔ account**: Pod Identity (service account → IAM role), access entries (IAM principal → cluster-admin) |
| 10 | Lambda | `POST /ingest/lambda` | **serverless entry points**: functions anyone can invoke → their execution role |

> **Ingesting more than one cloud account?** Add `?account=<id>` to the cloud sources.
> Identifiers like `i-…` and `sg-…` are unique only *within* an account, so without it
> two accounts that happen to share one merge into a single asset - and the engine then
> reports paths running through a machine that does not exist. Identities need no flag
> (an ARN already carries its account). Leave it off for a single-account estate and
> every id stays exactly as it is today.
>
> **More than one Kubernetes cluster?** Add `?cluster=<name>` to each cluster's dump, and give
> the merge gate the same name. Every cluster has a `prod` namespace, a `default` service
> account and a `cluster-admin`, so without it two clusters describe one imaginary cluster, and
> a route can enter one and end in the other's cluster-admin. One cluster needs no flag.

> **Complete snapshots: `?snapshot=`.** An ingest that describes a scope *in full* lets
> the engine forget what that scope no longer contains - see
> [Operating it](running.md#operating-it-freshness-backup--dr). Trivy (an image scanned by reference)
> and Semgrep (a repository named with `?repo=`) declare it on their own. For any other
> source you say it: `?snapshot=cluster:prod` on a dump of the whole cluster,
> `?snapshot=aws:123456789012/eu-west-1` on a whole account's network. Name only a scope
> you really sent in full: what it omits is retracted. `?snapshot=none` declares a report
> partial - a Trivy scan filtered by `--severity` or `--ignore-unfixed`, sent beside an
> unfiltered feed of the same image. A pull request's scan (`slug`/`sha`/`pr`) is never
> complete, and asking for it is refused.


Sources 6–8 are the **discovery** collectors: they extract the network/exposure
topology and IAM privilege-escalation graph automatically, so paths form without
hand-stitched ids.

---

## 2. Per-source snippets

### Trivy (dependency / image CVEs)

The report's `ArtifactName` becomes the Image node - pass the **full image ref**
you actually deploy. `slug`/`pr`/`sha` attach PR context so the action layer can
comment on the right pull request.

Scanning an archive instead - `trivy image --input image.tar`, the usual route in CI
without a Docker daemon - makes `ArtifactName` the file path, which matches no
workload. The Image node then takes the tag the archive was saved with, which Trivy
records in `Metadata.Reference`, so save it under the ref you deploy:
`docker save registry.example.com/payments-api:1.4.2 -o image.tar`. An archive saved
by image ID carries no tag at all: its node keeps the path, says why on the node
(`name_note`), and joins nothing.

```bash
trivy image --format json --output trivy.json registry.example.com/payments-api:1.4.2

curl -sS -X POST "$INGEST_URL/ingest/trivy?slug=$SLUG&pr=42&sha=$(git rev-parse HEAD)" \
  -H 'Content-Type: application/json' --data-binary @trivy.json
```

### CI build provenance (the link that connects code findings)

Emit this from CI **right after pushing the image**. Without it, Semgrep findings
float disconnected from the running workload. `image` must match the image Trivy
reported - its `ArtifactName`, or the saved tag for an archive scan; `repository` must
match Semgrep's `repo` (next step).

```bash
curl -sS -X POST "$INGEST_URL/ingest/build" -H 'Content-Type: application/json' -d '{
  "image":      "registry.example.com/payments-api:1.4.2",
  "repository": "payments-api",
  "slug":       "'"$SLUG"'",
  "sha":        "'"$(git rev-parse HEAD)"'"
}'
```

### Supply-chain provenance (cosign / SLSA / SBOM)

Emit this from CI after signing/attesting the image. It stamps the image with
its **trust signals** and **bill of materials**, assembled straight from the
tools you already run - no bespoke format:

```bash
IMG="registry.example.com/payments-api:1.4.2"
syft "$IMG" -o cyclonedx-json > sbom.json                          # SBOM (or: trivy image --format cyclonedx)
cosign verify "$IMG" >/dev/null 2>&1 && SIGNED=true || SIGNED=false # signature
# SLSA level from your attestation policy (cosign verify-attestation --type slsaprovenance "$IMG")
curl -sS -X POST "$INGEST_URL/ingest/supplychain" -H 'Content-Type: application/json' -d '{
  "image":       "'"$IMG"'",
  "signed":      '"$SIGNED"',
  "slsa_level":  3,
  "provenance_builder": "github-actions",
  "source_repo": "payments-api",
  "sbom":        '"$(cat sbom.json)"'
}'
```

`sbom` accepts the raw CycloneDX document above **or** a plain
`[{"name","version","type","purl"}]` list. Each component becomes a
`Library`/`Package` the image `DEPENDS_ON`. Include each component's `purl`: it gives
a Maven or npm component the name Trivy uses (`org.apache.logging.log4j:log4j-core`,
`@babel/traverse`), so it meets the CVE Trivy found on it instead of standing beside it. Set `signed:false` for an image whose
signature you couldn't verify - if it's reachable from the internet, the
`no-internet-to-unsigned-image` invariant fires (Violations view), and the kill
chain marks it **⚠ unsigned**. Omit `signed` entirely for "not assessed" (no
violation - unknown is not the same as unsigned).

### Semgrep (SAST weaknesses + secrets)

`repo` **must equal** the build provenance `repository`, so findings hang off the
same Repository node that `BUILT_FROM` links to.

```bash
semgrep --config auto --json --output semgrep.json

curl -sS -X POST "$INGEST_URL/ingest/semgrep?repo=payments-api&slug=$SLUG&pr=42&sha=$(git rev-parse HEAD)" \
  -H 'Content-Type: application/json' --data-binary @semgrep.json
```

### Cloud Custodian (cloud inventory + IAM)

The collector consumes a **bundle** that groups Custodian's per-policy
`resources.json` outputs by resource type. Assemble it like this (real AWS field
shapes - EC2 `PublicIpAddress`/`IamInstanceProfile`/`Tags`, ALB `Scheme`, IAM
`AttachedManagedPolicies`, S3 ACL grants, RDS `PubliclyAccessible`):

```bash
curl -sS -X POST "$INGEST_URL/ingest/custodian" -H 'Content-Type: application/json' -d '{
  "provider": "aws",
  "account_id": "123456789012",
  "policies": [
    { "policy": "elb-internet-facing", "resource": "aws.elbv2", "resources": [
      { "LoadBalancerName": "prod-alb", "Scheme": "internet-facing", "Tags": [{"Key":"app","Value":"payments"}] }
    ]},
    { "policy": "ec2", "resource": "aws.ec2", "resources": [
      { "InstanceId": "i-0abc", "PublicIpAddress": "203.0.113.10",
        "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/payments-profile"},
        "Tags": [{"Key":"Name","Value":"payments-vm"},{"Key":"app","Value":"payments"}] }
    ]},
    { "policy": "instance-profiles", "resource": "aws.iam-profile", "resources": [
      { "InstanceProfileName": "payments-profile",
        "Arn": "arn:aws:iam::123456789012:instance-profile/payments-profile",
        "Roles": [{"RoleName": "payments-role", "Arn": "arn:aws:iam::123456789012:role/payments-role"}] }
    ]},
    { "policy": "iam-admin", "resource": "aws.iam-role", "resources": [
      { "RoleName": "payments-role", "Arn": "arn:aws:iam::123456789012:role/payments-role",
        "AttachedManagedPolicies": [
        {"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"} ] }
    ]},
    { "policy": "s3-classified", "resource": "aws.s3", "resources": [
      { "Name": "customer-pii", "Tags": [{"Key":"classification","Value":"pii"}] }
    ]}
  ]
}'
```

**Keep the resources' own fields.** A load balancer's name and an RDS identifier are unique only
within one account and Region: the collector keys them with the bundle's `account_id` and the
Region in their `LoadBalancerArn` / `DBInstanceArn` (or a top-level `"region"` when the bundle is
one Region's export), and links a load balancer only to instances in its own Region, read from
their `Placement`. Custodian's output carries all of these; a bundle assembled by hand without
them keys by account alone.

**Include the `aws.iam-profile` policy.** EC2 reports an instance's *profile*, not its role, and
a profile is often named differently from the role inside it - Terraform and CloudFormation
name them separately. With the profiles in the bundle the instance reaches its real role; without
them the role is guessed to share the profile's name, and that join is marked as inferred and
weighs half. Roles are keyed on their `Arn`, as the IAM and network feeds key them, so the same
role is one node whichever source reported it. The step from instance to role is priced from the
instance's `MetadataOptions.HttpTokens`, as the network feed prices it, so the two feeds agree on
it; and when the network feed states a join Custodian could only guess, the stated one stays,
whichever arrives first.

**Keep each bucket's `Policy`.** A bucket is made public through its policy today - ACLs are
disabled by default on buckets created since April 2023 - and Custodian's `aws.s3` resources
carry the policy as AWS returns it. A statement that allows `s3:GetObject` to `"Principal":"*"`
with no condition narrowing who (a source IP or VPC endpoint, an organization, an account)
makes the bucket public and its data disclosed; one that allows only `s3:PutObject` makes it
exposed without disclosing it. The node says which (`public_via`: `bucket policy` or `acl`).
The bucket's Block Public Access settings, when the bundle carries them (the
`check-public-block` filter annotates them as `c7n:PublicAccessBlock`), close what they close:
`IgnorePublicAcls` the ACL grant, `RestrictPublicBuckets` the policy; the account-level
setting is not read. The roles and users a policy names - often in other accounts - get a
`HAS_PERMISSION` edge to the bucket: the access is on the bucket, whatever their own policies
say.

### Falco (runtime confirmation)

Point **falcosidekick**'s webhook output at the endpoint, or POST raw Falco JSON
(`-o json_output=true`). Each alert needs `output_fields["container.name"]`
(or `container.id`); include `container.image` so the runtime container links to
the scanned image (its ref must match Trivy's, after registry strip). In Kubernetes,
keep Falco's `k8s.pod.name` and `k8s.ns.name`: the alert then lands on the pod the
cluster dump describes, and marks its routes runtime-confirmed. With more than one
cluster, post to `/ingest/falco?cluster=<name>`, the name you give that cluster's dump.

```bash
curl -sS -X POST "$INGEST_URL/ingest/falco" -H 'Content-Type: application/json' -d '{
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "output": "A shell was spawned in a container",
  "output_fields": {
    "container.name": "payments",
    "container.image": "registry.example.com/payments-api:1.4.2",
    "k8s.pod.name": "payments-7d9", "k8s.ns.name": "prod"
  }
}'
```

### Kubernetes topology (auto-discovered exposure)

Post a raw cluster dump and PerspectiveGraph discovers the exposure topology -
`Ingress ──ROUTES_TO──▶ Service ──EXPOSES──▶ Pod ──ASSUMES──▶ ServiceAccount
──ASSUMES──▶ Role` - with no hand-stitched ids. Pods carry their image ref, so
they stitch to the scanned image automatically.

```bash
kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding \
  -A -o json > cluster.json
curl -sS -X POST "$INGEST_URL/ingest/k8s" -H 'Content-Type: application/json' --data-binary @cluster.json
```

Include `role` in that list: a Role belongs to its namespace, and the engine keys it with the
namespace, so a `deployer` in one namespace and a `deployer` in another keep their own rules.
With more than one cluster, name each dump's cluster - `?cluster=prod-eu` - so that two clusters'
`prod/web-sa` stay two service accounts.

**On EKS, the routes continue into the AWS account, and back** (OWASP Kubernetes Top 10,
K08 cluster-to-cloud lateral movement):

- **IRSA.** A service account annotated `eks.amazonaws.com/role-arn` gets an `ASSUMES` edge
  to that IAM role, keyed by ARN as the IAM feed keys it - so a pod's route continues into
  the role's escalations.
- **Escape to the node.** Add `node` to the `kubectl get` list and send the dump with
  `?account=<id>`: a pod that can escape its container (privileged, host namespaces,
  `hostPath`, dangerous capabilities) reaches its node's EC2 instance, read from the node's
  `providerID`, and from there the instance's role through IMDS, as the network feed draws it.
- **aws-auth.** Add `kubectl get configmap aws-auth -n kube-system -o json`: each IAM role or
  user it maps assumes the cluster roles its groups and username are bound to in *this*
  cluster, and `system:masters` is cluster-admin. aws-auth names a role without its IAM path,
  so a role created under a path does not meet the IAM feed's node.
- **Pod Identity and access entries** live in the EKS API, not in the cluster: the AWS
  connector reads them, or post an EKS bundle to `/ingest/eks` (see
  `backend/testdata/eks-sample.json`). Its cluster names must be the `?cluster=` the dumps are
  sent with. An access entry's `kubernetesGroups` are not read yet.

**From a pull request, send what the pull request renders.** A change to a manifest is
how most routes actually open - publish a Service, widen an RBAC rule - and until the
merge gate could attribute that change to a commit it stayed silent on exactly the kind of
work that opens a path. So the dump accepts the same `?slug=&sha=&pr=` the scanner
endpoints take, and stamps the objects it CONTAINS with them:

```bash
helm template . > rendered.json   # or: kustomize build . | yq -o json
curl -sS -X POST "$INGEST_URL/ingest/k8s?slug=$SLUG&sha=$(git rev-parse HEAD)&pr=42" \
  -H 'Content-Type: application/json' --data-binary @rendered.json
```

Two rules keep the attribution honest, and both are tested. Objects the dump only
*mentions* are never stamped: `cluster-admin` is shipped by Kubernetes and every
escalation ends at it, so attributing it to your commit would put that commit on every
route in the cluster. And a dump sent without those parameters - a nightly snapshot of the
live cluster, say - belongs to no commit and is stamped with nothing, exactly as before.

### Cloud network reachability (auto-discovered)

Post security groups + instances + VPC peerings; PerspectiveGraph derives who can
reach whom (`0.0.0.0/0` or `::/0 → internet_exposed`, SG-to-SG ingress → `CONNECTS_TO`,
carrying the ports it opens). Keep each rule's `IpProtocol`, `FromPort` and `ToPort`, and
the IPv6 sources under `Ipv6Ranges` where AWS puts them: exposure is decided port by
port, so the path shows *internet-exposed · tcp/443*, and a shell or database answering
the internet (SSH, RDP, the Kubernetes API, PostgreSQL…) gets a warning of its own. A
rule without a protocol counts as all traffic, as before. For **reachability
precision**, also include the instances' addresses (`PrivateIpAddress`,
`PublicIpAddress`, as `describe-instances` returns them) and `subnets` + `route_tables`
+ `network_acls`: an instance is then internet-exposed only on the ports that have a
public address to arrive at, a route to an internet gateway for their family and a NACL
that lets them through, first match by rule number - so an open SG on a private-subnet
instance, on one with no public IP, or behind an ACL that allows only 443 is no longer a
false positive, and ICMP alone is never an entry point. Omit them and the SG alone
decides (backward-compatible). The verdict is re-evaluated on every ingest: close a
security group and the next ingest retracts the exposure.

**ECS services** (awsvpc mode) are workloads too: add them as `ecs_services`, one per
service with its `serviceArn`, `taskRoleArn`, `assignPublicIp` and the `securityGroups` and
`subnets` of its network configuration (flattened from `describe-services` and
`describe-task-definition`; the AWS connector does this). A service is exposed by the same
rules as an instance - a public address only when it assigns one - takes part in SG-to-SG
reachability, and assumes its task role, which any of its containers can fetch.

```bash
# Assemble a bundle from: aws ec2 describe-security-groups / describe-instances /
# describe-vpc-peering-connections (see backend/testdata/cloudnet-sample.json).
# Optional precision: add describe-subnets / describe-route-tables /
# describe-network-acls as "subnets"/"route_tables"/"network_acls" (each instance
# carries its "SubnetId").
curl -sS -X POST "$INGEST_URL/ingest/cloudnet?account=123456789012" \
  -H 'Content-Type: application/json' --data-binary @cloudnet.json
```

### IAM privilege-escalation graph (auto-discovered)

Post the account's IAM reality and PerspectiveGraph builds the "BloodHound for
cloud" view: it flattens each principal's **effective** allowed actions (managed
+ inline + group policies, resolving the default policy version) and matches them
against known escalation primitives - `iam:PassRole` paired with a compute action
(`lambda:CreateFunction`, `ec2:RunInstances`, …), `iam:AttachUserPolicy`,
`iam:PutRolePolicy`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`, and
more. The five that act on the principal's own user or groups (`iam:AttachUserPolicy`,
`iam:PutUserPolicy`, `iam:AddUserToGroup`, `iam:AttachGroupPolicy`, `iam:PutGroupPolicy`)
count only for users: a role has neither. Each match draws a `CAN_ESCALATE_TO` edge to a synthetic **account-admin**
sensitive asset. A role whose trust policy admits `"Principal":"*"` is marked
`internet_exposed` (publicly assumable) - the seed of a full internet→admin path.

**Federated trusts.** A role that trusts GitHub Actions' OIDC issuer
(`token.actions.githubusercontent.com`) through `sts:AssumeRoleWithWebIdentity` gets an
*identity provider* node and an `AUTHENTICATES` edge into it. When the trust does not pin
`token.actions.githubusercontent.com:sub` to an owner - no `sub` condition, only the
audience checked, `repo:*`, a negation, or an owner with a wildcard in it - any workflow
in any repository on GitHub can assume the role: the node is marked `internet_exposed`,
the role `federated_trust_open`, and the route starts there. A trust pinned to a
repository (`repo:acme/payments:…`) or an owner (`repo:acme/*`) draws the node without
making it an entry point. AWS no longer accepts new trust policies of the open kind; roles
created before still have them. Other issuers - an EKS cluster's own, Cognito - are not
read yet.

```bash
# One call dumps every user, role, group and policy in the account.
aws iam get-account-authorization-details > iam.json
curl -sS -X POST "$INGEST_URL/ingest/iam?account=123456789012" \
  -H 'Content-Type: application/json' --data-binary @iam.json
```

> **Read-only & honest about scope.** The collector needs only the read-only
> `iam:GetAccountAuthorizationDetails` permission (the live connector adds
> `iam:GetPolicy` and `iam:GetPolicyVersion` to resolve permissions-boundary
> documents; all three are in `SecurityAudit`). It evaluates the parts of AWS
> policy logic that are unambiguous without request context: an **account-wide
> explicit Deny beats any Allow** (so a guardrail-denied action stops producing a
> phantom escalation), a **permissions boundary caps to the intersection** of itself
> and the identity policies (so a bounded principal is no longer confused with an
> unbounded one holding the same policy - see [the boundary
> lab](accuracy.md#the-engines-first-demonstrated-false-positive---found-then-closed)), and a
> primitive held only on **specific literal resources** yields a lower-probability
> edge (`resource_scoped`), since it lands only if those targets are themselves
> privileged. An `Allow` written with `NotAction` grants everything but what it
> names. Still not evaluated, by design: Condition keys and SCPs. An `Allow` under a
> condition counts as granted; a `Deny` under one, a `Deny` confined to specific
> resources (by `Resource` or `NotResource`) and a `Deny` written with `NotAction` are
> not applied - and an escalation that only a conditional `Deny` might block is
> reported at `0.5`, marked `deny_condition_unevaluated`. Each errs toward reporting
> rather than missing. Treat its findings as "worth confirming". See `backend/testdata/iam-sample.json` for the shape, and `make
> bench-cloudgoat` for the precision regressions that pin this.

### AWS Lambda (serverless entry points)

A function runs with an execution role, and the role's credentials sit in its environment:
whoever runs code in it holds the role. The collector draws each function as a `Function`
node that `ASSUMES` its role, keyed by ARN as the IAM feed keys it, so a route continues into
the role's escalations. The function is an entry point when anyone can invoke it:

- a **function URL** with `AuthType: NONE` whose policy lets every principal invoke the URL
  (the console adds that statement; a URL whose policy is not in the bundle counts as open);
- a **function policy** that lets `"Principal":"*"` call `lambda:InvokeFunction` with no
  condition narrowing who - anyone with an AWS account, which an attacker has.

The verdict is written either way, so removing a public URL takes the function off the
internet on the next pull. A function invoked through API Gateway is marked `invoked_by`
but not made an entry point: whether the API asks for credentials lives in API Gateway,
which is not read yet.

```bash
# Per function, what list-functions, get-function-url-config, get-policy and list-tags
# return (see backend/testdata/lambda-sample.json). The AWS connector assembles it.
curl -sS -X POST "$INGEST_URL/ingest/lambda" \
  -H 'Content-Type: application/json' --data-binary @lambda.json
```

### SSO / IdP federation (Okta → cloud - the modern front door)

Phishing/credential-stuffing an SSO user inherits every cloud role they federate
into. Post a directory export (Okta/Entra admin API) and PerspectiveGraph models
`IdentityProvider(internet) → User → ASSUMES → IAM_Role`. Set `federated_roles`
to the **role ARNs** each user can assume - they converge with the roles the IAM
collector discovered, so a no-MFA user federating into an admin/escalation role
completes the chain *internet → Okta → user → cloud admin*.

```bash
curl -sS -X POST "$INGEST_URL/ingest/sso" -H 'Content-Type: application/json' -d '{
  "provider": "okta",
  "users": [
    {"email":"alice@acme.com","mfa":false,"groups":["cloud-admins"],
     "federated_roles":["arn:aws:iam::123456789012:role/admin-role"]}
  ]
}'
```

`mfa:false` weights the IdP→user hop as easily phishable; `internet_login`
(default true) makes the IdP a seed. Build the payload from your IdP's API -
e.g. Okta `/api/v1/users` + the AWS-federation app's role mappings.

---

## 3. The two markers that make paths appear

The analyzer looks for routes from an **`internet_exposed`** node (seed) to a
**`crown_jewel`** node (target). **No marker on either side → no paths, empty
dashboard.** They are derived for you, but only if your data carries the signal:

- **`internet_exposed`** ← Custodian: ALB `Scheme: internet-facing`, EC2
  `PublicIpAddress`, S3 ACL granting `AllUsers` or `AuthenticatedUsers` (any AWS
  account), RDS `PubliclyAccessible: true`; IAM: a role whose trust admits `"*"`.
- **`public_access`** (open, not just reachable) ← an S3 grant that lets everyone
  READ, or a trust admitting `"*"` with no `Condition`. A sensitive asset carrying it
  is compromised as it stands and gets a direct-access path; one merely
  `internet_exposed` counts only when an edge reaches it.
- **`crown_jewel`** ← **tag your sensitive stores** with one of
  `classification` / `data-classification` / `data` / `sensitivity` =
  `pii | sensitive | confidential | restricted | secret`, or literally
  `crown-jewel=true`; or an IAM role with the `AdministratorAccess` policy.

If your real export doesn't carry these, set them directly on a node via
`/ingest/events` (see §5).

---

## 4. Identifier correlation (the make-or-break detail)

A path forms only when every source names the *same real asset* with the *same
node id*. The collectors compute it as:

```
<Label>:<first 16 hex of sha1( lowercase(key) )>
```

The key is what makes the asset unique in the system that owns it, its parts joined
with `|`: an image by its ref, a role by its ARN, a pod by `namespace/pod`, a package by
the name Trivy reports and its version, an instance by its account as well, and a load
balancer or database by its account and, when the export says it, its Region
(`account=…|region=…|name`). Use this helper to compute an id when you reference a node by hand:

```bash
pgid() { printf '%s' "$2" | tr 'A-Z' 'a-z' | shasum | cut -c1-16 | sed "s|^|$1:|"; }

pgid Image          "payments-api:1.4.2"                          # → Image:98b06dcdd2c1656f
pgid Container      "prod/payments-7d9c8f"                        # → Container:ba8322df0e416b02
pgid IAM_Role       "arn:aws:iam::123456789012:role/web-admin"    # → IAM_Role:519edff85bafd335
pgid Library        "org.apache.logging.log4j:log4j-core|2.14.1"  # → Library:df15149df9910e54
pgid VirtualMachine "account=123456789012|i-0web1"                # → VirtualMachine:ba33f006eb9f2f35
```

A Kubernetes object sent with `?cluster=<name>` is keyed `cluster=<name>|<key>`.

Practical rules:

- Use the **same image ref** in Trivy, build provenance and Falco. Registry
  prefixes are stripped automatically (`registry/…/payments-api:1.4.2` ≡
  `payments-api:1.4.2`), and Docker Hub `library/` is normalized - but anything
  more exotic must match exactly.
- Keep Semgrep `repo` == build provenance `repository` == supply-chain `source_repo`. A
  repository is keyed by that name alone, so two repositories with the same name under
  different owners are one node: if your estate has them, use `owner/name` in all three.
- Send Falco alerts with the **same `?cluster=`** as that cluster's dump: an alert is keyed
  to the pod it came from, `namespace/pod` in that cluster, and lands on the pod the dump
  describes.
- Give a classification of a **database** its `account` (per record, or `?account=` for
  the report) and its `region`: a database name is unique only within one account and
  Region. Buckets need neither.
- Prefer setting markers through the native source (Custodian tags) so you don't
  have to hand-compute ids at all.

---

## 5. Network topology - now auto-discovered

Earlier this needed hand-stitched `/ingest/events`. It no longer does: the
**`/ingest/k8s`**, **`/ingest/cloudnet`** and **`/ingest/iam`** collectors (§2)
extract exposure, reachability and privilege escalation for you -
Ingress→Service→Pod, Pod→ServiceAccount→Role, internet-facing security groups,
SG-to-SG reachability, VPC peering, and `CAN_ESCALATE_TO` edges to account-admin.
Feed the raw `kubectl get -o json`, AWS `describe-*` and
`get-account-authorization-details` output and the topology appears.

You can still hand-author edges via `/ingest/events` for anything the collectors
don't cover (computing endpoint ids with the `pgid` helper from §4):

```bash
LB=$(pgid LoadBalancer ingress-prod); C=$(pgid Container payments)
curl -sS -X POST "$INGEST_URL/ingest/events" -H 'Content-Type: application/json' -d '{
  "source": "topology", "kind": "relationship",
  "nodes": [{ "id": "'"$LB"'", "label": "LoadBalancer", "name": "ingress-prod",
              "properties": { "internet_exposed": true } }],
  "edges": [{ "type": "EXPOSES", "from": "'"$LB"'", "to": "'"$C"'", "exploit_probability": 0.9 }]
}'
```

Edge types: `EXPOSES`, `ROUTES_TO`, `HOSTS`, `CONNECTS_TO`, `ASSUMES`,
`HAS_PERMISSION`, `BUILT_FROM`, `DEPENDS_ON`, `AFFECTS`. Labels: `LoadBalancer`,
`VirtualMachine`, `Container`, `VPC`, `Database`, `Bucket`, `Repository`,
`Image`, `Library`, `User`, `IAM_Role`, `ServiceAccount`, `CVE`, `Weakness`,
`Misconfiguration`, `Secret`.

**The vocabulary is closed, and the endpoint enforces it**: a label or edge type outside
these lists is rejected with `400`, naming the offending value. It has to be closed,
because downstream code treats it as a bounded set - the AI layer renders the target's
label and each hop's edge type into a prompt, and the Apache AGE store interpolates the
label into Cypher. Enforcement used to live in the AGE store alone, so the in-memory
backend accepted anything; it now sits at the ingest door and again at the single writer
into the graph, where a value that arrives by another route is dropped and logged rather
than stored.

---

## 6. Verify a path formed

Wait one analyzer interval (`ANALYZER_INTERVAL`, default 30s) after ingest, then:

```bash
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ posture { criticalPaths kevOnPaths runtimeConfirmed } attackPaths { score nodes { name label } } remediationPlan { title coveragePct } }"
}' | jq
```

`criticalPaths > 0` means correlation worked. Open the dashboard for the kill
chains, the graph, and the **Remediation** plan. (See the Postman collection in
this folder for ready-made queries.)

### Quantify risk, simulate fixes, export for compliance

Once paths exist, four analyses turn "here are the routes" into decisions:

```bash
# Monte Carlo: P(sensitive asset compromised) with a 95% CI, over the whole graph.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ riskSimulation(iterations: 5000) { anyCompromiseProbability expectedCompromised crownJewels { name compromiseProbability ciLow ciHigh } } }"
}' | jq

# K-shortest: the top routes to one sensitive asset (id or name), best first.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ kShortestPaths(target: \"customers-db (PII)\", k: 5) { score nodes { name } } }"
}' | jq

# What-if: cut an edge (from/to accept id or name) and see the residual risk.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ whatIf(cuts: [{from: \"public-deployer\", to: \"account-admin (effective)\", type: \"CAN_ESCALATE_TO\"}]) { removedEdges riskReduction expectedReduction afterRisk { anyCompromiseProbability } } }"
}' | jq

# OSCAL: the posture as a NIST 800-53 assessment-results document for GRC tooling.
curl -s "$API_URL/export/oscal" | jq '.["assessment-results"].results[0].findings[].title'
```

`riskSimulation` is reproducible per `seed`; what-if runs the same trials
before and after, so the delta is the cut's effect, not Monte Carlo noise.

Each path also reports the **provenance** of its score so it isn't false
precision: `confidence` + `confidenceLabel` (high/medium/low) summarize how its
hops were weighted, and each `steps { weightBasis }` is `kev`/`epss`/`runtime`
(observed evidence) or `cvss`/`severity`/`heuristic` (an estimate). Turn on
`THREATINTEL=on` to upgrade CVE hops from severity guesses to KEV/EPSS evidence -
which raises the confidence of paths that rest on really-exploited CVEs. (Caveat:
EPSS is a *marginal* exploitation rate, not a per-edge traversal probability - fed
as-is on purpose so calibration corrects the bias; see README "Honest probabilities".)

The bare product `∏p` is only the baseline; each path also exposes **three honest
uncertainty views**: the correlation band `[score, scoreUpperBound]` (the
independence assumption), a 90% Bayesian credible interval `[scoreCiLow, scoreCiHigh]`
(how well we know the inputs), and an **attacker-profile mixture** `profileScores`
(`Σ P(c)·∏ p(e|c)` over commodity/criminal/apt, anchored on each hop's own
probability, retunable via `ATTACKER_PROFILE_PRIORS`). The headline `riskSimulation` carries a Wilson CI plus a
Beta-resampled credible band. Point estimates are unchanged; what's added is how much
to trust them.

### Close the loop: verify a fix, then own it

A remediation you can't trust is a scaffold. Each generated fix records the edge
it cuts, so the API *verifies* it by simulating the removal - the plan shows
`verification { verified pathsEliminated riskReductionPct expectedReduction }`, i.e.
"this provably removes N paths and drops risk by X%", not just "here's a YAML". Each proof is a
full what-if over the graph, so ask for them one fix at a time -
`remediationPlan(title: "…") { verification { … } }` - rather than across the whole
plan: one request may run at most 20 such analyses (what-ifs, verifications, custom
risk simulations, k-shortest searches), and the rest of its heavy fields answer with an
error. Then turn a path into an **owned, tracked ticket** so it actually gets done:

```bash
# Open a ticket (admin when auth is on). One open ticket per path; with
# TICKET_WEBHOOK_URL set it's also POSTed to your tracker (Jira/GitHub/SOAR).
curl -s -X POST "$API_URL/tickets" -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","owner":"secops@acme"}' | jq
curl -s "$API_URL/tickets" | jq                        # the work board
curl -s -X POST "$API_URL/tickets/tk-abc123/close"      # mark it done
```

### Validate against reality (red-team / BAS)

A modeled path is a hypothesis. Feed the verdict back so the engine earns trust
with evidence - wire your BAS platform (Caldera, AttackIQ, SafeBreach…) or a
human to post the result of testing a path:

```bash
# outcome ∈ confirmed | refuted | partial (reference a path id), or missed
# (a real path the engine didn't surface - describe it in route). source required.
curl -s -X POST "$API_URL/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","evidence":"atomic T1190"}' | jq
curl -s "$API_URL/validations" | jq .metrics    # precision / recall over the tested subset
```

Each tested path then shows a **✓ validated real / ✗ refuted** badge, and the
overview a **Validation** precision card. It's evidence on what was *actually*
tested - not a global precision/recall claim. Set `VALIDATIONS_PATH` to persist
(the calibration report flags an `in-memory` dataset otherwise).

Those verdicts also feed **probability calibration** (`{ calibration { … } }`): each
captures the path's predicted score, so the report grades it (Brier/ECE + a reliability
diagram), cross-validates a recalibration map, segments by path structure, tracks a
detection axis, and folds it all into one **diagnosis** -
`recalibrate-first | structural (#6) | detection-axis (#7) | per-basis (P1) | low-resolution | inverted-order` -
the answer to "and therefore what should we build?". You don't need real infra to exercise
it: `make calibration-selftest SCENARIO=…` draws verdicts from a known reality and the
gate must name the cause (also a deterministic CI test). A "Brier over time" trend on
the Overview lets you watch the evidence accumulate.

### Triage a path you've decided about

Not every path is a fire to fight - some you accept, some are false positives,
some a control outside the graph already covers. Record that decision so the
board reflects reality (and so the next analyst sees *who* decided and *why*):

```bash
# Suppress a path (admin when API auth is on). reason ∈
# accept-risk | false-positive | mitigating-control | duplicate. owner required.
curl -s -X POST "$API_URL/suppressions" -H 'Content-Type: application/json' -d '{
  "pathId": "ap-1a2b-3c4d", "reason": "mitigating-control",
  "owner": "secops@acme", "note": "WAF blocks this", "ttlDays": 30 }' | jq

curl -s "$API_URL/suppressions" | jq            # the triage board (incl. expired)
curl -s -X DELETE "$API_URL/suppressions/ap-1a2b-3c4d"   # un-suppress
```

`pathId` is the `attackPaths { id }` value (stable for a seed→sensitive-asset pair).
Suppressed paths drop out of the overview's **active** count and the
`riskSimulation` doesn't change - suppression is a *view* decision, not a graph
edit. Set `SUPPRESSIONS_PATH` so decisions survive a restart (otherwise they are
in-memory only). In the dashboard, use **⊘ suppress / triage** on any path and
the **Show suppressed** toggle on the list.

> Tip: when a kill chain shows a **"⚠ heuristic join · N%"** badge, the link was
> *inferred* (e.g. container→image by tag/name, not digest) - verify it before
> acting, or mark the path **false-positive** if the correlation is wrong.

---

## 7. Troubleshooting - "I see no attack paths"

Work down this list; it is almost always one of these:

1. **No seed** - nothing is `internet_exposed`. Check §3; mark an entry point.
2. **No target** - nothing is `crown_jewel`. Tag a sensitive store (§3).
3. **Seed and target exist but aren't connected** - the topology edge between
   them is missing (the §5 gap). Add the `EXPOSES`/`ROUTES_TO` edge.
4. **Ids don't match across sources** - the image ref or repo name differs. Use
   `pgid` to compare; align Trivy/build/Falco image refs and Semgrep `repo`.
5. **Ingest returns 5xx** - check the backend logs; a malformed payload is
   rejected per-source, an unknown collector name 404s.
6. **Data is in but stale** - give it one `ANALYZER_INTERVAL`; the analyzer only
   recomputes when the graph changed.

---

## 8. Run it continuously

A pilot is a few manual POSTs; production is the scanners wired to fire on their
own cadence:

- **CI (per PR / per build):** add the Trivy + build-provenance + Semgrep POSTs
  as a job step after you build the image, passing `?slug=&pr=&sha=` from the CI
  context. PR comments then land only on findings that sit on a real path.
- **Cloud (hourly/daily cron):** run Custodian, assemble the bundle, POST to
  `/ingest/custodian`. Re-posting is idempotent (deterministic ids + upserts).
- **Discovery (daily cron):** dump `kubectl get -o json`, the AWS `describe-*`
  bundle and `aws iam get-account-authorization-details`, POST to `/ingest/k8s`,
  `/ingest/cloudnet` and `/ingest/iam`. Each re-post is idempotent, so drift in
  exposure or IAM escalation surfaces as new/closed paths between runs.
- **Runtime (continuous):** point falcosidekick's HTTP output at
  `/ingest/falco`.

Start narrow - one app with a known internet entry point and a known sensitive
store - confirm a path end-to-end, *then* widen the scanners' scope.

**Deploying it on Kubernetes.** The Helm chart in `deploy/helm/perspectivegraph`
brings up backend + dashboard + Postgres+AGE + NATS in one command (or point it at an
external Postgres/NATS with `postgres.enabled=false`/`nats.enabled=false` - see
[the database matrix](../OPERATIONS.md#3-the-database-postgresql--apache-age) for which
services can host AGE at all). The
default install is *unauthenticated with in-memory governance* - fine for a demo
inside a trusted cluster, but for anything reachable beyond it, turn the controls
on: `--set auth.apiTokens="$(openssl rand -hex 16):admin"` (bearer auth),
`--set ingest.hmacSecret=…` (signed ingestion), and `--set persistence.enabled=true`
so suppressions, tickets, validations, MTTR history and the **audit log** persist
across restarts. All of those except the audit log can live in Postgres instead
(`GOVERNANCE_BACKEND=postgres`, shared by every replica); the audit log is a
single-writer hash chain, so the chart refuses to render with `backend.replicas > 1`
while persistence is on, and the post-install notes flag any control you left off. Full hardening recipe: the "Hardening a real deployment"
section of the README above.

### Keep it fresh (so it can't drift into fiction)

Complete snapshots (`GRAPH_SWEEP`, on by default) already retract what an image scan or
an account pull no longer lists; feeds that cannot vouch for a whole scope - a Falco
alert, a Custodian filter, a partial dump - need a TTL. Once feeds run on a cadence, set **`GRAPH_TTL`** to a few feed-cycles (e.g.
`168h`). Each observation stamps `last_seen`; the analyzer then removes anything
not re-seen within the window, so a deleted pod or torn-down security group stops
producing a **phantom path** instead of lingering forever. Make the TTL
comfortably longer than your slowest feed's interval, so one briefly-missed scan
doesn't evict a still-present asset. Watch it via `status { prunedNodes
prunedEdges lastPrunedAt }`, the dashboard footer (*“pruned N stale”*), or
`perspectivegraph_graph_pruned_{nodes,edges}_total`. The graph is **derived**
state - rebuildable by re-ingesting the feeds - so a lost AGE database is a
re-seed, not data loss; back Postgres up (`pg_dump`) for history.

### Manage on trends, not snapshots

Once it runs continuously, the temporal layer turns passes into a history. Set
**`HISTORY_PATH`** so it survives restarts, then track exposure over time:

```bash
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ history { openPaths resolvedPaths mttrSeconds oldestOpenSince trend { at criticalPaths riskPct } } }"
}' | jq
```

Each path also exposes `openForSeconds` (the dashboard's *“open 5d”* badge) and
`reopens` (*“⟳ reopened N×”* - a path that came back after being fixed, i.e. a
deploy reintroduced it). **MTTR** is the mean *resolved − first_seen* over paths
that closed - the accountability number for management reporting. The overview
plots the trend as a sparkline: chase a rising line, show a board a falling one.
