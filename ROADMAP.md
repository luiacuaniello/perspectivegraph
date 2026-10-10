# Roadmap

Where PerspectiveGraph is, and where it's going. This is intentionally honest about
what is and isn't done, for the same reason the engine reports its own calibration:
a status you can check beats one you have to take on faith.

**No dates.** What follows is ordered by how much it would move the project, not by
when it will land. Items marked *(scaffolded)* have the structure in place but are not
wired for production; *(not started)* is exactly that.

**On 1.0.** The version says the *interface* is stable - the GraphQL schema, the ingest
contract, the operational endpoints, the environment variables and the CLI, all governed
by [API stability](docs/API-STABILITY.md) and machine-guarded in CI. It does **not** say
the model has been validated in the field: nobody has yet run this over a real estate,
tested the paths it surfaced and fed the verdicts back, and the README opens by saying so.
Those are separate claims, and everything below is what is still open.

Contributions to any of these are welcome - open an issue first so we can agree on
the shape.

## Coverage

The engine correlates any cloud into the same graph; the limit is how many clouds
have a live connector. The connector framework is agentless and pull-based, so
adding one is a bounded piece of work, not a rewrite.

- **Multi-account AWS: collection done, Organizations discovery not.** `AWS_ROLE_ARN`
  takes one role per account and a pass pulls them all, each account's assets qualified
  with the id AWS reports for its own credentials (`sts:GetCallerIdentity`) - so
  identifiers that are unique only *within* an account (`i-…`, `sg-…`) no longer collapse
  two machines into one, and a route that crosses an account boundary says so. An account
  whose role fails costs that account's assets for the pass, not the estate's. No
  Organization is required: a read-only role in each account is enough. *(done - see
  `internal/connector/aws`, verified on fixtures; not yet exercised against real
  accounts)*
  What is still open is **discovery** - enumerating the accounts with
  `organizations:ListAccounts` instead of listing their roles - and it is gated on having
  an Organization to build against. *(not started)*
- **OpenStack connector.** Much of Europe's public cloud runs on OpenStack, and we know
  of no open attack-path tool that reads it. One read-only connector covers those
  providers: Nova servers, Neutron ports, security groups, routers and floating IPs for
  reachability; Keystone role assignments and application credentials for identity -
  mapped onto the existing ontology, so the analyzer and the scoring run unchanged.
  OpenStack offers a tenant no policy simulator, so there is no free oracle to grade it
  against as there is on AWS: what the engine claims there has to be checked by trying
  it. *(not started)*
- **GCP and Azure: read a graph that already maps them.**
  [Cartography](https://github.com/cartography-cncf/cartography) collects both, and
  collecting them again here would be work spent on what exists. The plan is to read its
  graph into this ontology rather than to write two more collectors. Azure exists here
  as fixtures only - a mapper with no live transport - and that stays the place to
  start for anyone who wants a native connector instead. *(not started)*

## IAM depth

The identity half is where cloud attack paths actually live, and it's where the most
precision is left on the table.

- **Permission boundaries.** Evaluated. A boundary caps effective permission to the
  intersection of itself and the identity policies - no explicit `Deny` needed - so a
  boundary that strips a privesc primitive now removes the escalation edge instead of
  being invisible. This one was found the honest way rather than reasoned about: `make
  boundary-lab-aws` stands up two roles with a byte-identical privesc policy differing
  only in a boundary, and on a real account the engine reported *both* as escalating
  while AWS denied one. `GetAccountAuthorizationDetails` returned the boundary and the
  connector's role/user structs discarded it. The fix carries `PermissionsBoundary`
  through the connector (fetching the boundary's document when the bundle omits it) and
  intersects it in the evaluator, alongside the existing resource-scoping logic. A
  boundary whose document cannot be read is reported but scored as *unverified*, since
  an `AdministratorAccess` boundary is a common no-op and dropping the edge would turn a
  false positive into a miss. The lab is now the regression test: it runs the engine and
  AWS side by side and fails on any disagreement. *(done - the oracle measured it, and
  measures it still)*
- **SCP and RCP evaluation.** Service Control Policies can deny what an identity policy
  allows, and Resource Control Policies what a resource policy allows. The engine reads
  neither, so it can surface an escalation or an access that a guardrail blocks -
  `redteam -compare` shows where on an account that has them, because AWS's evaluator
  applies SCPs. Needs Organizations data (see above), which gates it; AWS's policy
  simulator does not evaluate RCPs, so those have to be settled with real requests.
  *(not started)*
- **Condition keys.** Deliberately not evaluated: a condition cannot be decided without
  the request's context, so an `Allow` under one counts as granted, and a `Deny` under
  one is not applied, with what it might block reported as unverified. A `Deny` confined
  to specific resources, or written with `NotAction`, is ignored for the same reason:
  each of these over-reports rather than misses. `NotAction` and `NotResource` on an
  `Allow` are read, since 1.28.3. This is documented in the IAM package, and is a design
  boundary, not a bug to fix.

## Empirical calibration

The scores are expert estimates, not field-calibrated numbers. Closing that needs
genuine `refuted` verdicts - paths the engine surfaces that fail when actually
attacked - from an authority independent of the engine.

- **The IAM half is wired and verified against live AWS.** `make redteam-aws` settles
  the engine's privilege-escalation claims against AWS's own policy evaluator - a free,
  read-only dry run that applies the SCPs and condition keys the engine's policy reader
  skips. It creates nothing and needs no vulnerable infrastructure, and it has already
  earned its keep: the permission-boundary false positive above was found this way and
  then fixed. *(done - see `internal/redteam`)*
- **Exploited outcomes, for the path scores themselves.** The IAM oracle deliberately
  does **not** rescale `S(P)`, and cannot: every internet-origin path contains a hop no
  API can settle - whether an attacker gets code execution on the exposed host - so
  those verdicts are one-sided and a calibration set built from them is censored. What
  the oracle measures honestly is escalation *precision*, where both outcomes are
  observable. Rescaling the path scores needs real exploitation against a disposable lab
  account, because the unsettleable hop is "did the attacker get code execution" and no
  API answers that. `deploy/redteam-lab` specifies that environment; it is a written
  specification, not runnable Terraform. *(specified, not built - see `deploy/redteam-lab`)*
- **Condition keys: the oracle no longer mistakes them for refusals.** The engine reads an
  `Allow` as unconditional, so it claims escalations that only apply under `aws:SourceIp`
  or with MFA. AWS answers those with `implicitDeny` **and** a `MissingContextValues` key,
  and the oracle used to read only the decision - recording a refutation whenever it had
  merely failed to evaluate the condition. It now reports those as unsettled, naming the
  keys, and they are excluded from the calibration set. Deciding whether such a grant
  actually holds needs the attacker's context (an `aws:SourceIp` inside the VPC probably
  matches; MFA on a machine identity never does), which is a judgement the oracle should
  not make for you. *(done - see `internal/redteam`)*
- **Resource-scoped grants: the oracle no longer refutes what it did not ask.** A
  simulation with no resource named is evaluated by AWS against `*`, so a grant confined
  to specific resources answers `implicitDeny` - indistinguishable from holding no grant
  at all. The oracle used to record that as a refutation, while the engine legitimately
  surfaces such grants (scored down as `resource_scoped`). Denials now state that they
  settle only the *account-wide* claim, `redteam -resource <arn>` settles a scoped one,
  and `-compare` reports a scoped claim as unsettled instead of failing the engine for a
  question nobody asked it. *(done - see `internal/redteam`)*
- **Per-basis recalibration transfer.** The base rate of exploitability is a property
  of the environment and doesn't transfer between them; a per-provenance bias
  ("heuristic hops are systematically overstated by X") is a property of the model and
  might. The recalibration-by-basis is already computed; whether it transfers is an
  open empirical question, not a build task. *(open question)*

## Scale

The core pathfinding is polynomial and bounded - one shortest path per seed/jewel
pair, about a quarter of a second for a 10k-node / 45k-edge graph on a laptop
([measured](docs/SCALE.md#how-the-cost-grows)). The ceiling is not the algorithm, it's
the analysis architecture.

- **Event-driven incremental analysis.** Today every pass recomputes the whole graph
  from scratch: pathfinding, the Monte Carlo risk simulation, and the what-if
  remediation checks. Cost is `O(graph size) x O(1/interval)` regardless of how little
  changed, and the Monte Carlo simulation dominates it: 3.0 s for a pass's 2,000
  iterations on a 4,000-node graph ([measured](docs/SCALE.md#simulating-risk)). The
  fix is to recompute only what a graph delta actually affects. Incremental
  *snapshotting* exists (it cuts the fetch cost); incremental *analysis* does not.
  This is the real work behind "excellent performance at very high node counts", and
  it is not done. *(not started)*
- **Bounded remediation verification.** The what-if proof re-runs the simulation per
  fix. It now reads only the point estimate, on random draws shared between the "before"
  and the "after" - 0.08 s where it took 9.6 s, on that same graph - and is fetched
  lazily, so it no longer blocks the dashboard. It is still a simulation over the whole
  graph for each fix; a delta-based what-if would make it proportional to what the fix
  touches. *(mitigated; the root cause is the item above)*

## Assurance

The engine's *correctness* is measured and says so: calibration against recorded
verdicts, a CloudGoat precision/recall battery, an AWS policy oracle that has already
refuted it once. Its own *security* is measured less independently, and this section
exists to say by how much rather than let the automated gates imply more than they show.

- **Independent security audit.** The code passes `govulncheck`, `gosec`, CodeQL,
  `gitleaks`, Trivy and `staticcheck` on every build, and the images this project builds
  publish zero critical or high findings (the chart also runs NATS's own image, whose
  findings are fixed by NATS's releases and show in the chart's report until the next one
  is taken) - but every one of those is a tool looking for known
  shapes. Nothing here has been read by a security engineer who did not write it. For a
  tool whose output is a map of how to breach an organisation, that is the largest open
  assurance gap, and it is the one an adopting security team is most likely to ask about.
  Worth being precise about what it should be: a **code and application audit**, not a
  network penetration test. There is no hosted service to test - the deployment belongs
  to the adopter - so the target is this repository plus the hardening guidance in
  [OPERATIONS](docs/OPERATIONS.md). *(not started)*
- **What has been done instead, and what it is worth.** An adversarial self-assessment
  (September 2026) went after the ingest → analyzer → outbound-write path and found five
  real issues: the destination of forge writes taken from ingested data, a prompt-injection
  containment bypassed by two fields it did not cover, application scoping enforced on
  reads but not on the governance records behind them, upstream error bodies echoed to API
  callers, and an unsanitised property reaching a generated manifest. All five are fixed
  and carry regression tests, and the ones that changed a stated guarantee are written up
  in the [threat model](docs/THREAT-MODEL.md). It is recorded here as a **self**-assessment
  because that is what it is: performed by the author of the code, so it shares the code's
  blind spots by construction. It does not close the item above. *(done - and not a
  substitute)*
- **OSS-Fuzz enrolment.** The parse boundary is already fuzzed - a target for every
  collector's parser, in `backend/internal/ingestion/fuzz`, and for the redaction and
  policy-unescaping code beside them - seeded on every build and explored weekly by
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml). OSS-Fuzz would add the two
  things a self-hosted schedule cannot: CPU-months instead of minutes, and findings
  produced by infrastructure that is not the maintainer's. The targets exist, so this is
  an onboarding task rather than a build one. *(not started)*

## What this is not becoming

To keep the roadmap honest, some things are deliberately absent:

- Not a runtime agent or an EDR. Falco alerts are ingested as a signal; the engine
  stays posture-and-reachability, not a sensor.
- Not a broad CVE scanner. It consumes scanner output, it doesn't replace the scanner.
- Not a hosted SaaS in this repository. The control plane and billing of a hosted
  offering are out of scope for the open-source engine.
