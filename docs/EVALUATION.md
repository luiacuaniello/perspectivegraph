# Evaluating PerspectiveGraph

A proof of concept that ends in a decision rather than an impression. Each stage below
says what it proves, what it costs, and what "done" looks like - so you can stop at any
of them with an answer instead of a feeling.

**The question worth answering** is not "does it run". It is:

> Does it find a route through *my* estate that I did not already know about - and can I
> trust the answer enough to act on it?

Everything here is read-only until stage 2, and the first two stages need no deployment
at all.

## Before you start: the three long poles

The software is not what sets your calendar. These are, and none of them is fast to get
inside a large organisation, so start them on day one and run the stages while they move:

1. **A PostgreSQL with the Apache AGE extension.** This is the one that surprises people:
   **AWS RDS/Aurora and Google Cloud SQL do not offer AGE**, so on those clouds you run
   the database yourself. Azure Database for PostgreSQL flexible server does offer it.
   Settle this first - [OPERATIONS §3](OPERATIONS.md#3-the-database-postgresql--apache-age)
   is the matrix and the recipes.
2. **A read-only cloud role.** Everything the AWS connector calls is inside the AWS-managed
   `SecurityAudit` policy. Nothing is ever written.
3. **A decision about who may see the output.** The graph is a map of how to attack you, so
   it is not a dashboard to leave open. If you use SSO, someone has to map directory groups
   to roles (`OIDC_GROUP_ROLES`) or your users will sign in successfully and see nothing.

## Stage 0 - thirty seconds, no deployment

Ask **AWS's own policy evaluator** which of your roles can reach administrator. One static
binary, one read-only API call per check, nothing created:

```bash
curl -sSL https://github.com/luiacuaniello/perspectivegraph/releases/latest/download/perspectivegraph_darwin_arm64.tar.gz | tar xz
./perspectivegraph redteam -roles -region eu-west-1
```

**What it proves.** That the privilege-escalation half of the engine agrees with AWS about
your real principals - and where it does not. Add `-compare` and it runs the engine over
the same account and **exits non-zero on every disagreement**; each one is a false positive
or a miss, in the engine or in your assumptions.

**Done when** you have looked at one disagreement and decided which side was right.

## Stage 1 - an afternoon, still no deployment

Point the collector at one account and read what it sees:

```bash
AWS_REGION=eu-west-1 ROLE_ARN=arn:aws:iam::<account>:role/perspectivegraph-readonly \
  make validate-aws
```

It prints the internet-exposed seeds it found **and** the security-group-open instances it
suppressed, each with the reason. That second list is the interesting one: an open security
group on a box in a private subnet is the classic false positive, and this is where you see
whether the engine avoids it *in your VPC* rather than in a fixture.

**What it proves.** That reachability is computed from your routing, not guessed from your
security groups.

**Done when** you have picked one suppressed instance and confirmed it really is
unreachable, and one seed and confirmed it really is exposed.

## Stage 2 - a day, the first real deployment

Now it needs somewhere to live (§ the three long poles) and something to correlate. Deploy,
then feed it what your scanners already produce - it does not scan anything itself:

```bash
# The hardened profile ships inside the chart - pull it once, edit it, keep it under
# your own change control.
helm pull oci://ghcr.io/luiacuaniello/charts/perspectivegraph --untar
helm install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  -f perspectivegraph/values-production.yaml \
  --set postgres.externalHost=db.internal --set ingress.host=pg.example.com
```

The [onboarding runbook](MANUAL.md#onboarding-runbook) has the per-source ingest calls. Feed
**at least** one scanner report and the cloud/IAM topology, or there is nothing to correlate
into a path.

**Before you believe an empty board, check that it was fed.** An empty result means either
"no route exists" or "nothing arrived", and those deserve opposite reactions:

```bash
curl -s localhost:8080/graphql -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"query":"{ ingestCoverage { source events nodes lastSeen stale } }"}' | jq
```

Any source you expected showing `stale: true` or no events is an ingestion problem, not a
security finding.

**What it proves.** Whether findings from tools that do not talk to each other join into a
route across network, identity and supply chain.

**Done when** you can point at one path and say whether it is real. If it is - that is the
answer you came for. If it is not, the path detail shows every hop's probability and where
that probability came from, so you can say *which* hop is wrong; that is worth reporting.

## Stage 3 - the wedge, one repository

The reason the engine exists is to answer the question before the merge, not after the
deploy:

```yaml
- uses: luiacuaniello/perspectivegraph@v1
  with:
    mode: local
    aws-region: eu-west-1
    report: trivy.json
```

**What it proves.** That the check goes red only when *this commit* puts a sensitive asset
within reach - not when it adds a critical CVE to something nothing routes to.

**Done when** you have seen all three verdicts: a clean run, a blocked one, and an
`unknown`. The third matters most: it is what a broken scan or a wrong SHA produces, and it
fails the build by default rather than passing as green.

## What this will not tell you

Stated here so it is not discovered halfway through:

- **The scores are not field-calibrated.** They are the model's belief with its evidence
  named, not a measured frequency. Use them to rank and to cut routes; do not put the
  percentage in front of a board. The
  [calibration panel](MANUAL.md#closing-the-loop-calibration-against-observed-outcomes)
  withholds a verdict entirely until real outcomes exist.
- **One cloud is genuinely connected.** AWS is live; Azure is fixtures only; there is no GCP
  connector. Several AWS accounts can be pulled in one pass, but they are listed, not
  discovered - there is no AWS Organizations integration and no SCP evaluation.
- **It is not a scanner or a CNAPP.** It consumes what your scanners find. If they find
  nothing, it correlates nothing.
- **No third-party penetration test.** Review to date is automated and community-based; see
  the [threat model](THREAT-MODEL.md).

## Ending the PoC with a verdict

Four questions. If the first two are yes, it earned its place regardless of the rest:

1. Did it surface a route you **did not already know**?
2. Was that route **real** when you checked it?
3. Did the merge gate go red on a change that deserved it, and stay green on one that did
   not?
4. Could the people who need the output **get to it** - through your IdP, with roles that
   match your groups?

A no to (2) is worth reporting rather than discarding: a false positive with the hop that
caused it is the most useful thing this project can receive, and
[the CloudGoat benchmark](../backend/testdata/cloudgoat/README.md) exists so that a fix for
yours stays fixed.

## What it costs to run

Stages 0 and 1 cost nothing: read-only API calls, no infrastructure, no data leaves your
account. Stage 2 costs whatever your database and one small backend cost - the engine is a
static Go binary, and [SCALE.md](SCALE.md) has the measured per-pass numbers with the
method to reproduce them on your own graph size.

It collects **no telemetry**. Out of the box it opens no outbound connection at all: the
GitHub integration, the AI assistant and the KEV/EPSS feeds each stay dark until you set a
key or a flag.

## When you are ready to rely on it

[SUPPORT.md](../SUPPORT.md) is the policy: which versions get fixes, the security-fix
targets, and how to run this where change control applies. It is the document to hand to
whoever asks "what happens when there is a CVE in it".
