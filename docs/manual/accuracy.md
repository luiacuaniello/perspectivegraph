# Accuracy: calibration and validation

*Part of the [PerspectiveGraph manual](../MANUAL.md).* How the engine grades its own scores against real outcomes, and what it does with the result.

## Closing the loop: calibration against observed outcomes

The product, the bounds and the Monte Carlo are all *models*. What turns a model into a
production risk tool is checking it against reality. Each red-team/BAS verdict is recorded with the
path's **predicted score `S(P)` at test time** (captured server-side from the live analysis), so the
verdict log doubles as a calibration dataset: predicted probability paired with observed outcome
(confirmed→1, refuted→0, partial→0.5). From it `internal/validation` computes the standard scoring
rules - **Brier score**, **log loss**, **ECE** (expected calibration error) - plus a **reliability
diagram** (predicted vs observed per bucket) and a verdict (well-calibrated / calibrated-on-average /
over- / under-confident).
It also surfaces an *advisory* rescale (`observed/predicted`) rather than silently rewriting scores:
on a thin sample that would fit noise, and on a demo's synthetic outcomes it would be circular. This
is the demo→production boundary - the evidence that lets you defend a "55%" as a probability. Exposed
as the GraphQL `calibration` query and in the `GET /validations` response.

Knowing you're miscalibrated isn't enough; the report ([`diagnostics.go`](../../backend/internal/validation/diagnostics.go))
adds three lenses and folds them into one **diagnosis** so the gate is self-directing. (1) **Recalibration**:
an isotonic (pool-adjacent-violators) fit yields `brierRecalibrated` - the Brier a monotone rescale can
reach - plus the `recalibrationMap` (raw → calibrated) a consumer applies out-of-band; a residual that
stays high means the model lacks *resolution*, which no rescale fixes. (2) **Segments**: calibration split
by path structure (correlated/independent hops, long/short paths, captured on the verdict at test time);
error concentrated on correlated/long paths is structural → a correlation-aware model (**#6**). (3)
**Detection**: an operator can mark a confirmed verdict `detected`; a high catch rate on high-score paths
means the score over-predicts *undetected* compromise → a detection axis (**#7**). `diagnose()` returns
`recalibrate-first | structural (#6) | detection-axis (#7) | per-basis (P1) | low-resolution | inverted-order` -
so you build #6/#7 only when real verdicts prove the simpler fixes won't do.

Those real verdicts have to come from an authority *independent of the engine* - otherwise the loop is
circular and the calibration only measures how well the engine agrees with itself. That authority is AWS.

The red-team oracle ([`internal/redteam`](../../backend/internal/redteam)) turns each hop into an
independently-checkable claim and asks AWS's own policy evaluator, `iam:SimulatePrincipalPolicy`, to settle
it. That call is a **dry run**: it answers "would this be allowed" without performing anything, costs
nothing, and needs no vulnerable infrastructure to point at. And it applies what the engine's own
policy reader deliberately skips - **service control policies and condition keys**. So a principal the
engine reports as able to escalate, but that reality stops, comes back **denied**: a real false positive,
found without exploiting anything.

```bash
make redteam-aws                                                   # every role in the account
make redteam-aws PRINCIPAL=arn:aws:iam::123456789012:role/app      # one principal
make redteam-aws COMPARE=1                                         # engine vs AWS; non-zero exit on disagreement
```

`COMPARE=1` is the closed loop: it also runs the **engine** over the same account and prints the two
verdicts side by side, failing on any disagreement. A disagreement is a finding in either direction - the
engine over-reporting (a false positive) or missing a real escalation - so it is a check something can
fail, not a number to read.

Verified live on a real account: an administrator user comes back holding **all 20** escalation primitives
(each named), and a `SecurityAudit` read-only role comes back holding **none**. Both answers, for free,
with nothing created.

### The engine's first demonstrated false positive - found, then closed

`make boundary-lab-aws` settles the question the fixtures cannot: does the oracle catch a mistake the
engine genuinely makes? The lab is one variable wide - two roles with a **byte-identical** inline policy
granting `iam:AttachUserPolicy`, `iam:PutUserPolicy` and `iam:CreateAccessKey` on `*`, differing only in
whether a permissions boundary is attached. The boundary allows just `s3:Get*` and `ec2:Describe*`, so the
intersection strips the privesc grant - no explicit `Deny` needed, which is how boundaries are actually
used and precisely the case a policy reader that ignores them gets wrong.

Measured on a real account, it caught one:

| | engine, before the fix | AWS (`redteam`) | |
|---|---|---|---|
| `…-unbounded` (control) | `CAN_ESCALATE_TO account-admin` | **ESCALATES** - 3 primitives named | agree |
| `…-bounded` | `CAN_ESCALATE_TO account-admin` | **no privesc** | **refuted** |

The engine emitted the escalation edge for *both*, because
[`GetAccountAuthorizationDetails`](../../backend/internal/connector/aws/sdk.go) returns the boundary and the
connector's `iamRole`/`iamUser` structs dropped it before ingestion ever saw it. The control matters as
much as the finding: without a role the oracle *allows*, an oracle that simply always answered "denied"
would look equally convincing.

**That false positive is now closed**, in the two places the data was lost and then unused:

1. **Carried through.** The connector maps `PermissionsBoundary` onto users and roles. A boundary is named
   by ARN and its document travels separately, so the transport also fetches any boundary policy the
   bundle did not include (`iam:GetPolicy` + `iam:GetPolicyVersion`, both read-only and both inside the
   same `SecurityAudit` grant). Failing to read one is not fatal - an unreadable policy must not sink the
   whole IAM feed.
2. **Applied.** [`actionSet`](../../backend/internal/ingestion/iam/privesc.go) now carries the boundary and
   intersects it: `Allows` and `BroadlyAllows` require *both* sides, and `IsAdmin` is false whenever the
   boundary is not itself admin-equivalent. A boundary **never grants** - it only subtracts - so a
   permissive boundary over an empty identity policy still yields nothing.

Two behaviours are worth stating because they are the honest, non-obvious half:

- A boundary of `AdministratorAccess` is a common **no-op**, so "has a boundary" is not "is safe". The
  intersection is computed; the escalation survives it, and the edge records `boundary_evaluated` so
  "checked and still escalates" is distinguishable from "never checked".
- A boundary whose document is **not in the input** (an uploaded dump that names it by ARN only) leaves
  the cap uncomputable. The edge is kept - dropping it would turn this false positive into a *miss* on
  every no-op boundary - but marked `permissions_boundary_unresolved` and scored down to `0.5`, so an
  unverified claim cannot be quoted as an established one.

The lab is now the **regression test**. It runs the engine over the account for real (`redteam -compare`
drives the live connector) alongside `SimulatePrincipalPolicy`, prints the two verdicts side by side, and
exits non-zero on any disagreement - in either direction, since a miss is as much a finding as an
over-report. The unit test in
[`boundary_test.go`](../../backend/internal/ingestion/iam/boundary_test.go) pins the same fixture under
`make test`, so the regression is caught without an AWS account at all.

**What the oracle could not see in its own lab.** Two of the three permissions the lab grants,
`iam:AttachUserPolicy` and `iam:PutUserPolicy`, act on the caller's own *user*. A role is no user and
belongs to no group, so they let a role grant power to users it cannot act as - not escalate. The engine
credited roles with them anyway, and with `iam:AddUserToGroup`, `iam:AttachGroupPolicy` and
`iam:PutGroupPolicy`, at 0.9; the oracle agreed, because it asks whether each action is allowed, and it
is. Found by re-reading this lab, not by any check. Both sides now skip those five techniques for a role,
from the same table, so they cannot drift apart. The lab's verdicts stand - the control still escalates
through `iam:CreateAccessKey`, which lets a role mint an administrator user's keys - but it now names one
primitive, not three. An outside check covers only the question asked of it.

All of it at zero cost, with nothing exploitable standing up anywhere. The lab creates only IAM entities -
free on every account, not merely free-tier - and an `EXIT` trap tears it down even if the script dies.

**What this can and cannot calibrate** - the distinction matters more than the feature:

- **It cannot rescale `S(P)`.** Every internet-origin path contains a hop no API can settle: whether an
  attacker obtains code execution on the exposed host. Such a path can be *refuted* but never *confirmed*,
  so a calibration set built from these verdicts is **censored** - it can only ever contain the outcome 0,
  the observed rate collapses toward zero, and rescaling on it would drive every score to the floor. That
  is an artefact of what the instrument can see, not a measurement. Worse, the verdict store scores a
  `partial` as the label **0.5**, so admitting the unsettleable paths would enter *the oracle's inability
  to ask* as a half-true observation and manufacture an "overconfident" reading out of ignorance.
  `redteam.CalibrationGrade` is the guard: only `confirmed` and `refuted` are admissible, and callers must
  gate `store.Put` on it. A test measures what admitting them would have cost.
- **It can measure escalation precision.** "This principal holds a privilege-escalation primitive" is a
  claim AWS answers *both* ways, on demand, for free. The sample is uncensored, so
  `redteam.AuditEscalations` yields a real number - reported with its **coverage**, since a precision of
  1.00 over 5% coverage says almost nothing.

One implementation note worth knowing, because getting it wrong silently corrupts the dataset: the oracle
never asks AWS about `iam:*`. AWS reads that as "may perform *every* IAM action", so a principal holding
one genuine privesc permission would come back denied - a false refutation. Instead the claim carries an
internal sentinel that the oracle expands into the concrete actions of every primitive in
[the shared detection table](../../backend/internal/ingestion/iam/privesc.go), and the claim holds when any
single primitive has **all** of its actions allowed - the same all-of rule the detector applies, from the
same list, so the grader cannot drift from what is being graded.

Full path-score calibration still needs real exploitation attempts against a **disposable lab account**,
because the hop it turns on - did the attacker obtain code execution on the exposed host - is the one no
API answers. [`deploy/redteam-lab`](../../deploy/redteam-lab) specifies that environment; it is a written
specification, not runnable Terraform. That remains the one piece of engineering that can move the scores
from *directionally honest* to *empirically grounded*, and it needs real exploits, not more model code.

### Entry points, refereed by AWS

`make entrypoints-lab-aws` does for exposure what the boundary lab does for escalation. It builds
resources on both sides of each 1.29.0 rule, has the engine read them through the live connector as a
`SecurityAudit`-only role, and takes the verdict from AWS wherever AWS gives one: ten bucket policies
judged by `GetBucketPolicyStatus`, three function URLs judged by an unauthenticated request - 403 is
closed, anything else got past authorization - two load balancers, an internet-facing one and an
internal one, judged by a plain HTTP request to each DNS name, and three APIs, judged by an
unauthenticated request to each route. Nothing runs and nothing behind them is
reachable: the functions have reserved concurrency 0, the buckets are empty and behind
`RestrictPublicBuckets`, the ECS services have no tasks. The load balancers bill by the hour, so a run
costs a few cents; it tears itself down.

Its first run on a real account caught four errors, all now fixed:

| | AWS | engine, before the fix |
|---|---|---|
| bucket open to `*` on condition of an `aws:Referer` | public | private |
| bucket open to `*` from `aws:SourceVpc` `vpc-*` | public | private |
| bucket open to `*` from `aws:SourceIp` `0.0.0.0/1` | public | private |
| function URL without authentication, created now, granted `lambda:InvokeFunctionUrl` only | 403 | open |

The three buckets share one cause. The reader treated every condition as narrowing who may call, except
TLS; AWS starts from the other end - public, unless a condition confines the statement to fixed values
of a short list of keys - and the reader now does too. The function is a rule Lambda added in October
2025: a new URL needs `lambda:InvokeFunction` as well. Twenty-three other checks agreed from the first
run, among them the ECS services (exposed only with a public address, a route and an open port, on the
ports the network ACL lets through), the retraction of a function whose URL is deleted, and a GitHub OIDC
trust pinned to one repository. AWS refused to create a trust open to every repository, as documented, so
that case stays a unit test.

Load balancers joined the lab when 1.30.0 taught the network feed to read them. The internet-facing one
answered the request (503: no task behind it) and the engine called it the entry point on `tcp/80`; the
internal one never answered and the engine called it no way in. The engine drew the route from the public
one to an ECS service in a private subnet - through the service's target group, with no task running - and
to a Lambda function, and kept the service itself unexposed. All agreed on the first run.

API Gateway joined in 1.31.0: an HTTP API with an open route and one behind a JWT authorizer, a REST
API with an open method, and a REST API whose policy lets everyone in, then denies everyone outside a
documentation range. AWS answered the open routes (503 and 500: the function behind them never runs),
refused the JWT route (401) and the confined API (403). The first run caught one error in the new code
before it shipped: API Gateway hands a REST API's policy back escaped, slashes included, the reader
could not decode it, and erring toward reporting it called the confined API open. With that fixed, the
engine agreed on all of it - the open routes, the route into each function, and no route through the
authorizer.

Block Public Access set on the whole account has a lab of its own, `make public-access-lab-aws`, free
because it builds two empty buckets and nothing else. Each carries a policy that lets anyone list and
read it; one is closed by its own `RestrictPublicBuckets`, the other only by the account's. AWS
referees twice: `GetBucketPolicyStatus` calls both policies public, and an anonymous request to each
gets `403 AccessDenied`. The engine agreed on both. Told nothing of the account's setting - what every
version before 1.32.0 saw, since none read it - it calls the second bucket open: a false positive on
every account that blocks public access account-wide. No stranger gets in at any point: each policy is
put only once a setting already closes it, and the lab refuses to run where the account already has a
setting of its own, so it never loosens one.

### The labs' record, on the Accuracy page

Each of these labs ends by writing what it found - every question it put to AWS, where AWS's answer
came from, what AWS said, what the engine said, and whether they agree - with the date, the Region
and the engine version (`git describe`) of the run. The records live in
`backend/internal/labrecord/records/`, one per lab, written by `scripts/lab-record.py`, and are built
into the binary: the dashboard's Accuracy page shows them under *Checked against AWS*, and the
GraphQL field `labRuns` returns them. So every instance shows how the rules of its own version were
checked, disagreements included - a record with one is still a record.

Only the checks AWS answered go into a record: S3's judgement of a policy, the answer a stranger's
request gets, IAM's policy simulator. The checks the entry-points lab makes against its own
construction - which ports a service exposes, which route a load balancer draws - stay in its output
and out of the record. Nor does a record say anything about a route as a whole: it settles the facts
a route's steps rest on, and whether a whole route can be walked is the calibration's question, above.
A record never carries an account ID: the script replaces any twelve-digit number, and the binary
refuses to load a record that still holds one.

The engine treats an `Allow` as unconditional - `Condition` is documented as deliberately out of scope, so
detection errs toward over-reporting. That means it claims escalations that in reality only apply under
`aws:SourceIp`, or with MFA present.

A `Deny` under a condition is the mirror case, and until 1.28.3 the engine got it wrong: it applied the
`Deny` as if it always held, and so missed an escalation that is real whenever the condition is not met.
It now does not apply it, and reports what it might block at `0.5`, marked `deny_condition_unevaluated` -
unverified, the same way an unreadable permissions boundary is. `redteam -compare` grades such a claim
`unsettled (conditional)` when AWS refuses it, because AWS answered for one request context: with a
`BoolIfExists` condition and no MFA key supplied, the `Deny` applies, which is the case the engine already
named. (In the same release an `Allow` written with `NotAction` - "everything except…" - started being
read at all; before, it granted nothing, and every escalation in it was missed.)

Asking AWS about one is subtler than it looks, and getting it wrong quietly corrupts the calibration set.
Measured against the real API, a grant carrying an unevaluated `Condition` comes back as:

```
decision: implicitDeny        MissingContextValues: ["aws:MultiFactorAuthPresent"]
```

Read the decision alone and that is a refutation. It is not: AWS is saying *"a Condition applies and you
gave me no value for it"*. Whether the claim is actually refuted depends on the attacker - an
`aws:SourceIp` restriction the attacker matches from inside the VPC leaves the escalation entirely real,
while MFA on a machine identity never holds. The oracle cannot know which, so it reports these
**unsettled**, names the keys, and [`CalibrationGrade`](../../backend/internal/redteam) keeps them out of the
dataset.

Two further details, both established by probing the live API rather than assumed:

- **The keys cannot be attributed to a particular permission.** AWS reports `MissingContextValues` on
  *every* action in the simulation, including actions the policies never grant - so "not granted at all"
  and "granted under a condition" are indistinguishable from a context-free simulation. The evidence
  therefore names the keys and stops there, rather than guessing which escalation was gated.
- **A genuine permit is not lost to the caution.** An unconditional grant still comes back `allowed` with
  no missing context even when other statements on the same principal carry conditions, so a real
  escalation is still confirmed.

### Resource scope: what an unscoped question can and cannot refute

The same trap appears one layer down. A simulation that names no resource is evaluated by AWS against `*`,
so it asks an **account-wide** question. Measured on the real API, a grant confined to a single user:

```
simulated with no resource        -> implicitDeny
simulated on the granted ARN      -> allowed
simulated on a different ARN      -> implicitDeny
```

The first line is indistinguishable from holding no grant at all - and the engine *does* surface such
grants, scored down as `resource_scoped`. So a plain denial refutes the account-wide claim only; treating
it as "this principal cannot escalate" would fail the engine for a narrower question than it answered.

Three things follow, all of them in the code:

- A denial says so: *"no escalation primitive is permitted account-wide … a grant scoped to specific
  resources would not appear here"*.
- `perspectivegraph redteam -principal <arn> -resource <resource-arn>` settles a scoped claim by naming
  the resource the grant covers.
- `-compare` reports a principal whose engine claim is `resource_scoped` as **unsettled** rather than a
  disagreement, since the two sides are not answering the same question. Settling it means re-running
  with `-resource`.

The engine's policy reader records only *whether* a grant was account-wide, not which resources it names,
so the oracle cannot discover the scoped resource on its own - you supply it. That is a deliberate line:
having the oracle parse policies to find its own answer is how a supposedly independent check quietly
becomes a second opinion from the same source.

## Validated against reality (precision & recall)

A modeled attack path is a hypothesis until something walks it. PerspectiveGraph
takes the verdict back in: a **red-team or BAS platform** (Caldera, AttackIQ,
SafeBreach, Cymulate…) - or a human - records whether a path is **confirmed**
(exploitable end-to-end), **refuted** (a false positive - tested, not
traversable), **partial**, or **missed** (a real path the engine *didn't*
surface). From those verdicts it computes the trust metric a security tool
otherwise hand-waves:

```
precision = confirmed / (confirmed + refuted)   # of surfaced+tested paths, how many were real
recall    = confirmed / (confirmed + missed)     # of real paths, how many we surfaced
```

```bash
# A BAS run (or a human) posts the result; admin when auth is on.
curl -s -X POST "$API/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","evidence":"atomic T1190"}'
curl -s "$API/validations" | jq .metrics      # precision / recall over the tested subset
```

It's deliberately **not** a global precision/recall claim (that needs exhaustive
ground truth) - it's "here's the evidence on what was actually tested", which is
how trust is earned. The dashboard's **Accuracy** page leads with the verdict and what it means
for how to read a score, then lists every recorded outcome - which route, who tested it, when -
with the statistics (reliability diagram, error scores, ranking quality, diagnosis) closed
underneath; each tested path shows **Proven by** / **Refuted by** the source that tested it.
Before the first outcome it gives no verdict and shows the half of every calibration point that
already exists: each open route's predicted probability with its 90% interval, on the 0-100% scale
the reliability diagram will use. It marks one route per score band, the one with the widest
interval, as **test first**. That is where an outcome moves the estimate most, and spreading the
first tests across bands keeps the sample from checking only the engine's confident predictions.
What the detection stack caught is on **Today**, since it is a fact about the estate rather
than about the scores. Set `VALIDATIONS_PATH` to persist. `make seed-validation` records synthetic verdicts on part of the live paths the
way a BAS run would: about 40% of them plus every one a runtime alert fired on, each confirmed
with probability equal to its score - so some likely routes fail and some unlikely ones work.
Those verdicts demonstrate the instrument; they are not evidence about the engine.

### Calibration: does the score mean anything? (the demo→production gate)

precision/recall tell you whether a *surfaced* path was real. Calibration asks the
harder, production question: does the **number** mean anything - do paths scored
~0.8 actually confirm ~80% of the time? Each verdict is captured **with the model's
predicted score at test time** (server-side, so the tester can't fudge it), turning
the verdict log into a calibration dataset. From it the engine reports the scoring
rules a forecaster is judged by:

```
Brier = mean (p - y)²                          # sharpness+calibration, lower better
ECE   = Σ (nₖ/N)·|meanPredₖ - obsRateₖ|         # binned calibration gap, lower better
```

plus a **reliability diagram** (predicted vs observed per bucket; points on the
diagonal are perfectly calibrated), an honest **verdict** (well-calibrated /
calibrated-on-average / overconfident / underconfident), and an **advisory rescale**
(`observed/predicted` - surfaced, *not* silently applied, since rescaling on a thin sample
is fitting noise).

The verdict needs **both** the mean and the bins before it says well-calibrated:

| verdict | mean gap | ECE | what it licenses |
|---|---|---|---|
| `overconfident` / `underconfident` | > 0.1 | - | the scores run hot / cold on average |
| `calibrated-on-average` | ≤ 0.1 | > 0.1 | only the average: no individual score may be read as a probability |
| `well-calibrated` | ≤ 0.1 | ≤ 0.1 | "when it says 70%, roughly 70% happens" |

The middle row exists because the mean alone cannot carry the last one. A score whose
outcomes do not depend on it at all can still predict the base rate on average - the
`low-resolution` self-test scenario has a mean gap of −0.006 and an ECE of 0.21 - and it
used to be labelled well-calibrated, which the Accuracy page (then called Trust) read aloud as "70% means
70%". It is also what too few samples per bucket honestly produce: ECE is noisy on small
data, so a per-score claim the data cannot support is withheld. The verdict describes the
pooled population; a miscalibration that differs by evidence basis can still hide inside a
well-calibrated pool, which is what the per-basis diagnosis is for.

```bash
curl -s "$API/validations" | jq .calibration   # brier, ece, verdict, reliability bins
# GraphQL: { calibration { samples brier ece verdict bins { low meanPredicted observedRate } } }
```

This is the artifact that lets an operator stand behind "55%" as a *probability*,
not a vibe - the line between a demo and a risk tool you can put in front of an
auditor. The dashboard renders it as a **Calibration** panel on the Overview.

#### Discrimination: does the *order* mean anything?

Calibration grades the number; it says nothing about whether the dangerous paths sit
above the harmless ones - and that order is what an operator works through. A score can
be perfectly calibrated and separate nothing, or order paths sharply while every number
it prints is wrong. So each calibration track also reports **AUC**: the probability that a
confirmed path outranks a refuted one, ties counted half.

```
AUC = P( score(confirmed) > score(refuted) ) + ½·P(tie)   # 0.5 = coin, 1 = perfect, <0.5 = inverted
```

It is graded twice on the path track: for **S(P)** (`discrimination`) and for **Priority**
(`priorityDiscrimination`) - the triage order itself, which is not a probability, so
nothing above could grade it. That is why every verdict now also records the path's
Priority *at verdict time*, captured server-side exactly like the score. A verdict
recorded before this existed, or against a path that was no longer live, carries none,
and simply does not count toward the triage-order grade.

- `Partial` verdicts are **excluded** - half credit is not a class to a ranking comparison.
- Each result carries an approximate **95% interval** (Hanley-McNeil). Perfect separation on
  a small sample would otherwise report zero width, so the error is evaluated at a
  half-count shrunk AUC; the published AUC is never shrunk.
- The **verdict** - `discriminates` / `indistinguishable-from-chance` / `inverted` - is
  withheld (`insufficient-data`) below **ten of each class**; the AUC is still shown.
- A modest `priorityDiscrimination` is partly by design: Priority also weighs target
  sensitivity and blast radius, so a refuted path to a crown jewel ranking high is the
  order doing its job.

```bash
# GraphQL: { calibration { discrimination { auc aucLow aucHigh verdict positives negatives }
#                          priorityDiscrimination { auc aucLow aucHigh verdict } } }
```

`make calibration-selftest` shows the two claims coming apart on synthetic verdicts: its
`overconfident` scenario is badly miscalibrated yet orders paths better than any other,
while `low-resolution` cannot be told apart from a coin. Those verdicts are generated,
so they prove the instrument, not the engine. The dashboard shows both orders under the
reliability diagram as **Score order** and **Triage order**.

#### Calibration diagnostics: "and therefore what should we build?"

Knowing you're miscalibrated isn't enough - you need to know *why*, so you don't
build the wrong fix. The report adds three diagnostic lenses over the same verdicts
and folds them into one **diagnosis**:

- **Recalibration** - a **cross-validated** isotonic (monotone) fit gives
  `brierRecalibrated`, the Brier a pure rescale can reach *out-of-sample* (k-fold, so it
  doesn't overfit exactly when data is thin - the real-world case). If it's good, you
  just apply the published `recalibrationMap` (raw → calibrated); the engine never
  silently rewrites scores. A `brierRecalibrated` that stays high means the model lacks
  *resolution* (can't separate real from fake) - the line past which a rescale can't help.
- **Segments** - calibration split by path structure (`correlated-hops` vs
  `independent`, `long` vs `short`). Residual error that concentrates on correlated or
  long paths is *structural* - the independence assumption - and points at a
  correlation-aware model (**#6**, Bayesian Attack Graph).
- **Detection** - of reachable (confirmed) paths an operator can report `detected`
  (caught/blocked). A high catch rate on high-score paths means the score over-predicts
  *undetected* compromise - the signal for a detection axis (**#7**, `P(reach ∧ ¬detect)`).

So the gate is honest and self-directing: `recalibrate-first` (apply the map) /
`structural (#6)` / `detection-axis (#7)` / `per-basis (P1)` / `low-resolution` /
`inverted-order` - you build #6 or #7 only when the evidence on real verdicts says the
simpler fixes won't do.

Whatever the diagnosis says about the *ranking* is read from
[discrimination](#discrimination-does-the-order-mean-anything), never inferred from the
lenses above, which measure the numbers:

| Score order verdict | What the diagnosis may say about order |
|---|---|
| `discriminates` | "the ranking is sound", with the AUC and its interval beside it - so a weak order that still beats chance is visible as one |
| `indistinguishable-from-chance` | `low-resolution`: the order cannot be told apart from chance, so no rescale can help |
| `inverted` | `inverted-order`: refuted paths outrank confirmed ones; first suspect verdicts recorded with confirmed and refuted swapped |
| `insufficient-data` | nothing: `recalibrate-first` says the rescale is indicated and the ranking is not yet graded |

A coin-flip or backwards order is settled before the structural (#6) branch - a
correlation-aware model on evidence that orders nothing is complexity without a
foundation - but after detection (#7) and per-basis, which carry their own evidence:
pooling bases that run hot and cold can flatten an order the per-basis map restores.

If the diagnosis ever points at #6, `make and-probe` (the `andprobe` decision tool)
answers the question that actually decides a Bayesian Attack Graph: does your
environment have real **AND semantics** (a compromise needing several distinct
prerequisites at once) or pure OR-reachability the Monte Carlo already models? It
counts the critical-path nodes whose incoming edges span multiple prerequisite
categories - an *upper-bound heuristic* (a plain graph can't tell AND from OR; that's
what a BAG adds), so it names candidates for your `refuted` verdicts to confirm. Near
zero means #6 is a no-op - fix `p(e)` instead. (`--all-nodes` inspects the whole
topology, not just attack-path nodes.)

AND-semantics is a property of **topology**, not of CVEs - so feed it *real* topology:
`make ingest-k8s` snapshots your current `kubectl` context
(`Ingress/Service/Pod/SA/RBAC → exposure + privilege-escalation + container-escape`
edges - the collector takes native `kubectl get ... -o json`) and ingests it. Point
`kubectl` at a local **kind + kubernetes-goat** cluster for a deliberately-vulnerable
one, then `make and-probe` reads the AND-signal off real cluster structure. (A
locked-down cluster - e.g. a default Docker Desktop k8s - yields zero AND candidates,
which is itself the answer: no #6 needed.)

Run as a **program, not a snapshot**: set `VALIDATIONS_PATH` so verdicts survive
restarts (the report flags an `in-memory` dataset otherwise), and watch the
`calibrationTrend` (Brier/ECE/sample-count sampled each pass) on the Overview to see
the evidence accumulate and the scores improve over time.

```bash
curl -s "$API/validations" | jq '.calibration | {verdict, brier_recalibrated, diagnosis, segments, detection}'
# Record whether a confirmed attempt was caught, for the detection axis:
curl -s -X POST "$API/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","detected":true}'
```

#### Self-test without real infrastructure

You don't need a deliberately-vulnerable environment to *exercise and test the
instrument itself*. `make calibration-selftest SCENARIO=...` (the `genverdicts`
subcommand) draws verdicts from a **known reality you control** and checks the
diagnostics name the right cause - exactly how you'd integration-test a calibration
system. It validates the *instrument*, never the engine's scores against the real
world (that still needs real verdicts):

```bash
make calibration-selftest SCENARIO=overconfident   # → "recalibrate-first"
make calibration-selftest SCENARIO=correlated      # → "structural (#6)"
make calibration-selftest SCENARIO=low-resolution  # → "low-resolution"
make calibration-selftest SCENARIO=detection       # → "detection-axis (#7)"
# scenarios: calibrated | overconfident | underconfident | correlated | low-resolution | detection
```

Each scenario injects a specific flaw (reality harder than predicted, correlated
hops, no resolution, heavy detection) and the gate must name it - so the tool both
seeds the dashboard and proves the diagnostics actually distinguish #6 from #7.
(Synthetic verdicts post their own calibration features; for a *live* path the
server-captured prediction always wins, so a real tester still can't fudge it.)

The same scenarios run as a deterministic **in-process CI test**
(`TestCalibrationScenarioDiagnosesEndToEnd`), so a regression in the gate logic fails
the build instead of surfacing months later on real data.

#### The on-ramp to *real* verdicts (the BAS bridge)

When you're ready to leave synthetic data, point the engine at a **deliberately
vulnerable target** (CloudGoat via the AWS connector, a local OWASP Juice Shop, a
manual pentest) - all authorized, your-own/sandbox infrastructure - and feed the
results back with zero custom integration. `make import-verdicts FILE=report.json`
(the `importverdicts` subcommand) reads a **tool-agnostic** attack report and matches
each finding to a live path by its target (sensitive-asset name) and optional entry, so a
tester reports *"I confirmed a path to account-admin"* without knowing internal ids:

```jsonc
{ "source": "pacu", "findings": [
  { "target": "account-admin", "from": "public-deployer", "outcome": "confirmed",
    "detected": false, "evidence": "iam privesc via CreatePolicyVersion" },
  { "target": "cluster-admin", "outcome": "refuted", "evidence": "SG blocks egress" },
  { "route": "s3-public -> export", "outcome": "missed", "evidence": "not modeled" } ]}
```

That's the whole loop closed on reality: **vulnerable target → ingest (AWS connector
`fixtures`/`sdk`, or a scanner) → live paths → BAS → `import-verdicts` → calibration**.
Set `VALIDATIONS_PATH` so the verdicts persist across a real engagement, and the
diagnosis - now on real data - decides whether #6/#7 are actually warranted.

**Zero-cost, real, in ~15 minutes (Trivy → log4shell).** No cloud spend, no AWS
account - just a genuinely exploitable local target. `make ingest-real IMAGE=<img>`
(the `ingestreal` subcommand) scans a vulnerable image with **Trivy** (real CVEs,
real CVSS; real KEV/EPSS with `THREATINTEL=on`) and wires the minimal topology so the
CVE sits *on* an internet → sensitive-asset path:

```bash
# stand up a real, exploitable log4shell (free), then ingest its real CVEs:
git clone https://github.com/vulhub/vulhub && cd vulhub/log4j/CVE-2021-44228 && docker compose up -d
make ingest-real IMAGE=<the vulhub image>          # → internet-lb → image → log4j-core → CVE-2021-44228 → sensitive-asset
# ...exploit the running target for real, then record the verdict:
make import-verdicts FILE=my-report.json           # {"target":"secrets-vault","outcome":"confirmed"}
```

The CVE, its severity and its KEV/EPSS are **real** (only the deployment topology is
modeled - use the `k8s` collector on a local cluster to make that real too). Now the
score rests on a CVE you can actually exploit, so the verdict calibrates the real thing.

**One command that runs the whole loop: `make validate-harness`.** It brings up a
genuinely-exploitable log4shell app, lets the engine surface the path, then *actually
exploits the live app* and takes the verdict from an **independent oracle** - did the
app make the JNDI callback? A callback ⇒ `confirmed`, none (patched / blocked / not
vulnerable) ⇒ `refuted` - so the outcome is real, not something you asserted (which is
why building your own vulnerable app is the wrong move: the verdict has to come from an
exploit that succeeds or fails on its own, and calibration needs the honest `refuted`
verdicts too). Repeatable; override `TARGET_IMAGE=…` to point at a patched build (to
harvest `refuted`) or another target. `scripts/validate-harness.sh`; needs docker + the
stack up.

**Real topology, not modelled: `make validate-harness-k8s`.** The log4shell harness
models the path (hardcoded edge probabilities); this one goes further. It stands up a
`kind` cluster with two misconfigured RBAC scenarios and lets the **k8s collector
discover** the topology, so the attack-path *score* is the engine's real output, then
exploits each path and takes the verdict from the Kubernetes API server's own RBAC
decision: a ServiceAccount with cluster-wide `secrets/read` reads a secret it shouldn't
(HTTP 200 ⇒ `confirmed`), while one with `bind` on clusterrolebindings tries to bind
itself to cluster-admin and is blocked by Kubernetes' anti-privilege-escalation (HTTP
403 ⇒ `refuted`). That refuted is a real **false positive** - the collector's escalation
heuristic over-reports the bind primitive - exactly the signal calibration exists to
catch. `SUFFIX=<x>` makes distinct samples so a loop accumulates volume; `DELETE_CLUSTER=1`
tears the cluster down. `scripts/validate-harness-k8s.sh`; needs `kind`.

**First contact with a real cloud account: `make validate-aws`.** The two harnesses above
run on synthetic topology; this points the **live AWS connector** at a real read-only
account (`describe-*` only, never a write) and prints what it discovered - the
internet-exposed seeds *and* the SG-open instances the route/NACL layer **suppressed**,
each naming why (private subnet via a NAT / transit gateway / egress-only IGW, or a NACL
that denies the internet). Eyeballing "exposed should be genuinely reachable, suppressed
genuinely private" is the honest test of reachability precision on data you didn't design.
Credentials come from the standard AWS chain; `AWS_REGION=<region>` is required,
`ROLE_ARN=<arn>` assumes a cross-account read-only role first (the "customer grants you a
role" model), and `INGEST_URL=<url>` also pushes the discovered events into a running
stack for full attack-path scoring. Read-only grant: the AWS-managed **SecurityAudit**
policy (covers `ec2:Describe*`, `iam:GetAccountAuthorizationDetails`, and the
`iam:GetPolicy`/`iam:GetPolicyVersion` used to resolve permissions boundaries).
`scripts/validate-aws-readonly.sh`; the same thing standalone is
`perspectivegraph awscollect -region <r> [-role <arn>] [-json] [-ingest <url>]`.

**Persistence is on by default in `docker compose`.** The stack mounts a
`perspective-govdata` volume (its ownership fixed by a one-shot `gov-init` so the
non-root, read-only-rootfs backend can write it) and defaults `VALIDATIONS_PATH` into it,
so a calibration program's verdicts accumulate across restarts. Set `VALIDATIONS_PATH=`
to go back to in-memory.

## KEV holdout: a calibration dataset that builds itself (optional)

Calibration normally needs verdicts, and verdicts normally need a red team. Most
installations have neither, so the Accuracy page reads *"insufficient data"* forever. The
KEV holdout fills part of that gap from public feeds alone.

The obvious version of this idea does not work, and it is worth being precise about why.
The engine derives a CVE hop's probability *from* KEV and EPSS: a CVE in KEV is assigned
0.95 by that very formula. Grading today's score against today's KEV membership would
therefore score the formula against its own input and report an excellent Brier that
means nothing.

The holdout breaks the circle with **time**:

1. Each pass **seals** a forecast for every CVE in the graph that is *not yet* in KEV,
   recording what the engine predicted from that day's evidence.
2. One window later (30 days by default - what EPSS itself forecasts over) the forecast
   is **graded** against an event that had not happened when it was sealed: did this CVE
   enter KEV in the meantime?

That is a genuine out-of-sample prediction, and it is the construction FIRST uses to
evaluate EPSS. A CVE already in KEV is never sealed - there is no forecast left to make,
and sealing it is exactly how the circularity would return.

```bash
THREATINTEL=on KEV_HOLDOUT=on KEV_HOLDOUT_PATH=/var/lib/pg/holdout.json make run-backend
```

Two things to expect, both structural:

- **Nothing appears for a window.** A forecast must be sealed before its outcome exists,
  so the dataset cannot be built retroactively. Without `KEV_HOLDOUT_PATH` it never
  matures at all, because a 30-day window outlives most uptimes; the backend warns when
  that path is unset.
- **The level will look pessimistic, and that is not the engine being wrong.** The graded
  event (CISA confirms and catalogues the CVE) is *narrower* than the modelled one (an
  attacker traverses this hop). So this track publishes **no recommended scale and no
  diagnosis** - applying its offset to the engine would be fitting a different question.
  What survives the mismatch, and what the track is for, is **discrimination**: whether
  higher-scored CVEs really do turn out exploited more often than lower-scored ones.

It appears as its own section on the Accuracy page and as `calibration.edge` in GraphQL,
never merged into the headline verdict - the same separation the `path` and `target`
scopes already enforce, for the same reason.
