# Sources and integrations

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Agentless connectors, topology discovery, supply-chain provenance, identity resolution and threat intelligence.

## Agentless connectors: pull, don't wait for an upload

A scanner report only helps once someone uploads it. **Connectors** invert that:
they reach *out* to a system on a schedule and pull its current state - no agent
to deploy, no one to remember to `curl`. The goal is the one that won the cloud
security market: *connect a read-only role and see your real attack paths in
minutes.*

Crucially a connector publishes onto the **same bus** as the webhooks, so it
reuses the entire pipeline unchanged - identity resolution, the graph, the
analyzer. The **`aws`** connector doesn't even add new parsing: it pulls the EC2
`describe-*` network state and IAM authorization details and feeds them straight
into the existing `cloudnet`/`iam` collectors. The **`azure`** connector adds a
thin mapping layer - Azure's native model differs, so NSG CIDR rules become security
groups, NSG **ASG** sources become SG-to-SG (the east-west micro-segmentation that
lets the exposed tier reach the sensitive asset), VMs become instances bound to their
NSGs and ASGs, and VNet peerings become VPC peerings, then the **same** `cloudnet`
collector parses the result. The acquisition sits behind a
swappable transport - **`fixtures`** (local JSON, so the whole pull pipeline is
provable with zero credentials) and a live SDK path (`aws-sdk-go-v2` for AWS,
read-only with optional cross-account `AssumeRole`; `azure-sdk-for-go` is the
wired extension point for Azure).

```bash
# Demo (no cloud account): pull from local describe-* / normalized JSON
CONNECTORS_ENABLED=aws,azure AWS_CONNECTOR_MODE=fixtures AZURE_CONNECTOR_MODE=fixtures \
  AWS_FIXTURES_DIR=./backend/testdata AZURE_FIXTURES_DIR=./backend/testdata
curl -s localhost:8081/connectors | jq   # per-connector health: last run, last error, events

# Live (read-only): assume a cross-account role and pull EC2 + IAM
CONNECTORS_ENABLED=aws AWS_CONNECTOR_MODE=sdk AWS_REGION=us-east-1 \
  AWS_ROLE_ARN=arn:aws:iam::<account>:role/perspectivegraph-readonly
# grant only: ec2:Describe*, iam:GetAccountAuthorizationDetails, iam:ListInstanceProfiles,
# iam:GetPolicy + iam:GetPolicyVersion (to resolve permissions-boundary documents)
# (all covered by the AWS-managed SecurityAudit policy - verified against a live account)

# Multi-account: one role per account, comma-separated, pulled in a single pass.
CONNECTORS_ENABLED=aws AWS_CONNECTOR_MODE=sdk AWS_REGION=us-east-1 \
  AWS_ROLE_ARN=arn:aws:iam::111111111111:role/perspectivegraph-readonly,arn:aws:iam::222222222222:role/perspectivegraph-readonly

# See what the live connector discovers before wiring it in (describe-* only):
AWS_REGION=us-east-1 ROLE_ARN=arn:aws:iam::<account>:role/perspectivegraph-readonly \
  make validate-aws       # internet-exposed seeds vs SG-open-but-suppressed, with reasons
```

**Several accounts, one estate.** `AWS_ROLE_ARN` takes a list, and each account's assets
are qualified with the account id AWS reports for its own credentials
(`sts:GetCallerIdentity` - no extra grant, it is allowed to every principal). That
qualification is not cosmetic: `i-…` and `sg-…` are unique only *within* an account, so
without it two accounts that happen to share an identifier collapse into one asset, and
the engine reports paths through a machine that exists in neither. An account whose role
has expired costs that account's assets for the pass and nothing more - the others are
still collected, and `GET /connectors` reports the error. No AWS Organization is needed:
a role in each account trusting the one the engine runs as is enough.

Connectors are **leader-only** (replicas don't multiply API calls), interval-driven
(`CONNECTOR_INTERVAL`), and observable via `GET /connectors` plus
`perspectivegraph_connector_*` Prometheus metrics. SDK mode uses the standard AWS
credential chain (env / shared profile / IRSA / instance role). The network pull also
reads route tables, NACLs and subnets, so an SG open to `0.0.0.0/0` on an instance in a
**private** subnet (NAT / transit-gateway egress, or a denying NACL) is *not* reported as
internet-exposed - the classic false positive that inflates attack-surface counts.

It also resolves each instance's **IAM instance profile** to the role behind it and draws
`instance --ASSUMES--> IAM_Role`. That edge is what joins the network half of the graph to
the identity half: without it, *"the internet reaches this box"* and *"this role owns the
account"* sit in disconnected components and the canonical AWS path - internet → instance →
IMDS → role → privilege escalation (the Capital One shape) - cannot form. The hop is priced
on the instance's real IMDS posture: `HttpTokens=required` (IMDSv2) makes a blind SSRF
insufficient, while IMDSv1 hands the credentials to a single GET. Cloud Custodian prices the
same hop from the same field, so the two feeds agree on it.

## Topology discovery (no hand-stitched IDs)

`make seed-discovery` posts a raw Kubernetes dump (`kubectl get … -o json`), a
cloud-network export (AWS `describe-*`) and an IAM authorization dump
(`aws iam get-account-authorization-details`) - the same shapes the `aws`
connector pulls live. PerspectiveGraph **auto-discovers**
the exposure/reachability topology no scanner produces:

- **Kubernetes** → `Ingress → Service → Pod → ServiceAccount → Role`, surfacing
  e.g. *internet → ingress → pod → cluster-admin* - a privilege-escalation path
  found from cluster config alone. RBAC is modeled in depth: beyond
  wildcard/`admin`-named roles, a role that grants an **escalation primitive**
  (`create pods`, `read secrets`, `bind`/`escalate` roles, `impersonate`,
  mint SA tokens) draws a `CAN_ESCALATE_TO` edge to a synthetic **cluster-admin**
  - BloodHound-for-Kubernetes, not just a name check.
- **SSO / identity federation** (Okta, Entra, …) → the modern front door:
  `IdentityProvider(internet) → AUTHENTICATES → User → ASSUMES → IAM_Role`. The
  federated role is ARN-keyed, so it converges with the IAM graph - a **no-MFA**
  Okta user who federates into an admin/escalation role surfaces the whole chain
  *internet → Okta → user → cloud admin*, with the no-MFA hop weighted as easily
  phishable.
- **Cloud network** → internet-facing security groups, SG-to-SG reachability and
  VPC peering, surfacing e.g. *internet → web tier → PII database*.
- **IAM privesc graph** ("BloodHound for cloud") → flattens each principal's
  effective permissions, matches them against known escalation primitives
  (`iam:PassRole`+compute, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, …;
  those acting on the principal's own user or groups only for users)
  and draws `CAN_ESCALATE_TO` edges to a synthetic **account-admin** sensitive asset.
  A role trusting `"Principal":"*"` is flagged internet-exposed, surfacing
  *internet → publicly-assumable role → CAN_ESCALATE_TO → account compromise*.

This is what turns "demo that works because the IDs line up by hand" into
"discovery on real infrastructure".

Sensitive-asset classification isn't purely tag-driven either: an untagged
`Database`/`Bucket` whose name carries a strong sensitive-data signal (pii,
customer, payment, credential, …) is **inferred** a sensitive asset and marked
`crown_jewel_basis="inferred:<signal>"` - so a missed tag doesn't hide a target,
and the guess is auditable (the dashboard shows *sensitive asset (inferred)*). An
explicit owner tag always wins.

## Supply-chain provenance (SBOM, signing, SLSA)

The modern breach often starts before runtime - a tampered build, an unsigned
image, a poisoned dependency. The **supply-chain collector** (`/ingest/supplychain`)
stamps each image with its trust signals and bill of materials, assembled from
the tools you already run:

```bash
syft "$IMG" -o cyclonedx-json > sbom.json
cosign verify "$IMG"                                  && SIGNED=true  || SIGNED=false
cosign verify-attestation --type slsaprovenance "$IMG" # SLSA build attestation
curl -X POST "$INGEST/ingest/supplychain" -d "{\"image\":\"$IMG\",\"signed\":$SIGNED,\"slsa_level\":3,\"sbom\":$(cat sbom.json)}"
```

The image gets `signed` / `slsaLevel` / `sbomComponents`, and every SBOM
component becomes a `Library`/`Package` the image **DEPENDS_ON** (the full bill,
not just the vulnerable parts Trivy flags). Crucially, an **unsigned image is
treated as a tampering vector**: the built-in invariant
**`no-internet-to-unsigned-image`** fires when one is reachable from the internet,
and the kill chain flags the image **⚠ unsigned** - so "this prod image isn't
signed *and* sits on a path to the sensitive asset" surfaces as a policy violation,
not a footnote. `sbom` accepts a plain component list or a CycloneDX document
(raw `syft`/`trivy` output), so real tool output drops in unchanged.

## Identity resolution you can trust (confidence + explainability)

Correlation across tools is only as good as the joins underneath it. When the
normalizer **infers** a link rather than reading one a tool asserted - e.g.
stitching a runtime container to the image a scanner reported - it now records
**how** and **how sure**: a digest pin is an exact identity (`1.0`), a tagged
ref is strong (`0.85`), a bare name is a weak correlation worth verifying
(`0.6`), and a weaker join lowers the stitched edge's probability so a path
resting on a shaky correlation scores below one built on a hard identity. The
provenance rides on the node (`resolutionMethod` / `resolutionConfidence` /
`resolutionAlias`) and surfaces in the kill chain as a **"⚠ heuristic join · N%"**
badge - so an analyst can *see, and distrust,* a heuristic correlation instead
of mistaking it for ground truth. A guess never replaces a fact: when one source
states a link another inferred, the stated one stays whichever arrives first, and
an inferred write only confirms it is still there.

## Threat-intel: KEV + EPSS (optional)

Severity is a label; *exploitation* is a fact. Enable the threat-intel layer and
PerspectiveGraph enriches every CVE with **CISA KEV** (the catalog of
vulnerabilities *known exploited in the wild*) and **FIRST EPSS** (the
probability of exploitation in the next 30 days). KEV/EPSS reweight the `AFFECTS`
edge so path scores reflect real exploitation likelihood, not a severity guess -
and a KEV CVE on a *reachable, runtime-confirmed* path is the strongest
prioritization signal there is: theoretical → exploited-somewhere → exploited-here.

```bash
THREATINTEL=on make run-backend   # fetches live from CISA + FIRST (cached)
```

Disabled by default (zero network); the `AFFECTS` edge then keeps its
severity-derived weight.
