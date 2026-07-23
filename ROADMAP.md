# Roadmap

Where PerspectiveGraph is, and where it's going. This is intentionally honest about
what is and isn't done, for the same reason the engine reports its own calibration:
a status you can check beats one you have to take on faith.

**No dates.** This is a 0.x project in active development; the version number means
the API can still change. What follows is ordered by how much it would move the
project, not by when it will land. Items marked *(scaffolded)* have the structure in
place but are not wired for production; *(not started)* is exactly that.

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

- **Permission boundaries.** Not evaluated today, so a boundary that caps an
  otherwise-admin principal is missed. The `get-account-authorization-details` bundle
  already carries the data; this is a bounded addition modelled on the existing
  resource-scoping logic. *(not started, but the data is already ingested)*
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

- **Wire the red-team oracle to live AWS.** The harness exists and is proven on
  fixtures: it turns each path hop into an independently-checkable claim and grades it
  against `iam:SimulatePrincipalPolicy`, `sts:AssumeRole` and a network probe. The
  live oracle is inert until wired to a disposable lab account, and the randomized lab
  is a Terraform scaffold. *(scaffolded - see `internal/redteam` and `deploy/redteam-lab`)*
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
