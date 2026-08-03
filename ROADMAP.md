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

- **AWS Organizations, multi-account.** Today one account is ingested at a time. Real
  estates are multi-account under an Organization, read through a single role. This
  is the most-requested gap and the one a real prospect hits first. *(not started -
  needs an Organization to build and test against, which the demo environment lacks)*
- **GCP live connector.** No GCP today. The ontology and analyzer are
  provider-neutral; this is a new collector against the GCP asset APIs. *(not started)*
- **Azure live connector.** Azure exists as fixtures only - the mapper is there, the
  live SDK transport is not. Promoting it to live is smaller than GCP because the
  shape already exists. *(scaffolded)*

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
- **SCP evaluation.** Service Control Policies can deny what an identity policy
  allows, and the engine doesn't see them - so it can surface an escalation an SCP
  blocks. Needs Organizations data (see above), which gates it. *(not started)*
- **Condition keys and NotAction/NotResource.** Deliberately out of scope: condition
  keys can't be evaluated without request context, so the engine treats an Allow as
  unconditional and over-reports rather than misses. This is documented in the IAM
  package, and is a design boundary, not a bug to fix.

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
pair, ~270ms for a 10k-node / 45k-edge graph on a laptop. The ceiling is not the
algorithm, it's the analysis architecture.

- **Event-driven incremental analysis.** Today every pass recomputes the whole graph
  from scratch: pathfinding, the Monte Carlo risk simulation, and the what-if
  remediation checks. Cost is `O(graph size) x O(1/interval)` regardless of how little
  changed, and the Monte Carlo plus per-fix what-if simulation dominate at scale (a
  mid-size estate already pushes remediation verification into tens of seconds). The
  fix is to recompute only what a graph delta actually affects. Incremental
  *snapshotting* exists (it cuts the fetch cost); incremental *analysis* does not.
  This is the real work behind "excellent performance at very high node counts", and
  it is not done. *(not started)*
- **Bounded remediation verification.** The what-if proof re-runs a full simulation
  per fix. Fetching it lazily (done) stops it blocking the dashboard, but the
  underlying cost is unchanged; a delta-based what-if would fix it at the root.
  *(partially mitigated)*

## What this is not becoming

To keep the roadmap honest, some things are deliberately absent:

- Not a runtime agent or an EDR. Falco alerts are ingested as a signal; the engine
  stays posture-and-reachability, not a sensor.
- Not a broad CVE scanner. It consumes scanner output, it doesn't replace the scanner.
- Not a hosted SaaS in this repository. The control plane and billing of a hosted
  offering are out of scope for the open-source engine.
