# Scoring and priority

*Part of the [PerspectiveGraph manual](../MANUAL.md).* How a route gets its probability, how honest that probability is, and what decides which route to fix first.

## Risk scoring

What the resulting number is the probability *of* - and the three readings it does not
support, including "80% likely this year" - is stated in
[positioning](../POSITIONING.md#what-a-score-is-the-probability-of). This section is how it
is computed.

Each edge carries an exploit probability `p ∈ (0, 1]`. The probability that a full path is
exploitable (assuming independence, for tractability) is the product of its edge probabilities:

```
S(P) = ∏ p(vᵢ, vᵢ₊₁)
```

We convert to a traversal cost `w = -ln(p)` so that **maximizing `S(P)` becomes a shortest-path
problem** (minimizing `Σ w`) solvable with Dijkstra. See
[`backend/internal/analyzer`](../../backend/internal/analyzer).

The product assumes the hops are **independent**. When they share a common cause (one weakness
gating several steps) they are positively correlated, and the product is then a *lower* bound for
"all hops succeed"; the comonotonic (Fréchet) upper bound is the weakest single hop, `min p`. So
rather than dressing up `S(P)` as exact, each path also exposes a `scoreUpperBound` (= `min p`) and
a `correlatedHops` flag (set when ≥2 hops rest on the same weight basis, or declare the same
`weight_cause`) - the true exploitability lies in `[score, scoreUpperBound]`, and a wide band says
the independence assumption is doing the work. Hops that declare the same `weight_cause` - one CVE,
one leaked credential - are not independent at all: they stand or fall together, so the score counts
that cause once, at its weakest hop, exactly as the risk simulation samples it.

A second, orthogonal uncertainty is *epistemic*: how well is each `p` known at all? Each edge is
modelled as a **Beta(α,β) posterior** with mean `p` and concentration κ scaled by the weight basis's
confidence - many pseudo-observations for kev/runtime, few for a heuristic guess - plus one for each
observation an edge's `evidence_count` reports (κ = κ(basis) + n: evidence only ever tightens it)
([`uncertainty.go`](../../backend/internal/analyzer/uncertainty.go), Marsaglia-Tsang gamma→beta, zero
deps). Propagating those posteriors through the product gives a 90% credible interval per path
(`scoreCiLow`/`scoreCiHigh`), and re-driving the Monte Carlo from them (an outer epistemic loop
around the inner reachability trials) replaces the old flat ±30% sensitivity band with one the
evidence justifies. The inner trials are the same for every draw, so the band's width is what the
inputs cause, not the sampling noise of 400 trials (which alone used to make it ±4 points). Point estimates are untouched; only their *trust* is now quantified.

The independence assumption itself is addressed at the root by an **attacker-profile mixture**
([`profiles.go`](../../backend/internal/analyzer/profiles.go)). Hops are correlated through a latent
variable - the attacker's capability - so the score is marginalized over a small set of profiles c
(commodity/criminal/apt), each with a prior `P(c)` and a skill that shifts every hop's success
log-odds, scaled by the hop's skill-sensitivity (≈0 for a public KEV exploit, ≈1 for a heuristic
guess): `p(e|c) = σ(logit p + δ(e) + skill(c)·sens(basis))`, `S(P) = Σ P(c)·∏ p(e|c)`. δ(e) anchors
the profiles to the hop's own probability - it is the shift at which `Σ_c P(c)·p(e|c) = p(e)` - because
EPSS, a KEV floor or a severity mapping describe the attackers out there taken together, not one median
attacker. Conditioning makes independence honest *within* a profile; marginalizing reintroduces the
correlation the bare product drops, and nothing else: one hop reads exactly `p`, and a path reads
between its independent score and its weakest hop. (Without δ the weak-attacker-heavy priors dragged
every figure below its inputs - one hop at 0.9 read 0.78.) The per-profile breakdown (`profileScores`, `mixtureScore`) is the *"72% vs an APT, 18% vs
commodity"* read a SOC triages on. Priors are operator-tunable via `ATTACKER_PROFILE_PRIORS`; the
naive `Score` stays as the independent baseline.

**Where the traversal runs.** Node *and edge* properties are stored as **native
agtype** in Apache AGE, so the graph is genuinely queryable. The per-pass
critical-path search uses the **in-process Dijkstra by default** - a polynomial,
bounded algorithm that is the right engine for "all best paths every pass".

A DB-side finder is available as an **opt-in** (`ANALYZER_DB_PATHS=true`): a Cypher
variable-length match (`MATCH p=(a)-[*1..N]->(b) WHERE a.internet_exposed AND
b.crown_jewel`, bounded by `ANALYZER_MAX_HOPS`). It is honestly *not* a perf win
for the batch - AGE has no weighted shortest-path, so this **enumerates** paths,
which is unbounded in the worst case on dense/cyclic graphs. It is therefore
safe-railed (server `statement_timeout` + `LIMIT`, plus a client deadline that
**falls back to Dijkstra** on a runaway query) and best reserved for bounded or
targeted queries. The store-contract test asserts the DB finder and Dijkstra
agree on scores, and documents the recall bound when a path exceeds `maxHops`.
Either way the per-pass snapshot is materialized for the policy-invariant engine
and the Monte Carlo risk model, which need the full edge set.

### Scaling the analyzer

Three layers keep the per-pass cost flat as the graph grows, in increasing order
of how much they assume:

- **Change-detection (always on).** The analyzer skips a pass entirely when the
  store's write version hasn't moved since the last one - a steady graph costs
  nothing but a version read (a periodic forced rescan bounds staleness for the
  multi-replica case, where another replica's writes don't move *this* process's
  counter).
- **Parallel pathfinding (on by default).** Each internet-exposed seed runs an
  independent Dijkstra over the same immutable adjacency, so the searches fan out
  across a bounded worker pool (`ANALYZER_WORKERS`, default = `GOMAXPROCS`). The
  per-seed results are assembled in seed order before the final sort, so the
  output is **byte-for-byte identical to a sequential run** regardless of worker
  count - parallelism is a speedup, never a behavior change (asserted by
  `TestParallelMatchesSequential`). On a 10k-node / 64-seed synthetic graph the
  `BenchmarkPathfindWorkers` benchmark shows ~2.9× at 8 workers.
- **Incremental snapshotting (opt-in, `ANALYZER_INCREMENTAL`).** Instead of
  re-reading the whole graph each pass, the analyzer keeps it resident and patches
  it with just the elements observed since the last pass - a store `DeltaStore`
  capability (`SnapshotSince`, filtered on the same `last_seen` the pruner uses, so
  only the changed slice leaves Postgres). It still recomputes *all* paths (an
  attack path can change non-locally), but skips the dominant fetch +
  deserialization cost on a large AGE graph. Correctness is fenced: a full re-read
  rebuilds the cache on the first pass, right after a prune (deltas carry no
  deletions), periodically as a drift safety net, and on any delta error - and
  `TestIncrementalMatchesFullSnapshot` asserts the delta path reports the same
  paths as a one-shot full read. Graph size, snapshot mode (`full|delta`), and
  pathfinding latency are all exported to `/metrics`.

For load-testing the whole pipeline end-to-end, `perspectivegraph genload` (and
`make seed-load`) POSTs a large synthetic attack surface to the ingest webhook.

### Beyond the single best path

The per-path product answers "how exploitable is *this* route". Three analyses go further:

- **K-shortest paths (Yen's algorithm).** The top-K highest-probability loopless routes to a
  sensitive asset, so cutting the single best edge doesn't hide the near-best alternates.
- **Monte Carlo risk quantification.** Each trial realizes every edge independently (present
  with probability `p`; edges declaring the same `weight_cause` together), then checks
  sensitive-asset reachability. Every draw is a function of the trial and the edge itself, not of
  its position, so two graphs that share an edge share its fate in every trial. The fraction of trials where a
  sensitive asset is reachable is an unbiased estimate of its **compromise probability** - accounting for
  path multiplicity and shared edges that `∏p` can't - reported with a 95% Wilson confidence
  interval (sampling error) **and** a Beta-resampled credible band (input uncertainty; see above).
  This is the `P(at least one sensitive asset compromised)` a CISO actually asks for. It is *also*
  marginalized over the attacker-profile mixture (`mixtureCompromiseProbability = Σ_c P(c)·R_c`, with
  `R_c` conditioning every edge on `p(e|c)`), so the headline shares the per-path score's correlation
  model rather than assuming independent edges - the independent number stays as the baseline, plus a
  per-profile `profileCompromise` breakdown.
- **What-if simulation.** Remove a set of edges (a proposed remediation) and recompute paths +
  risk on the *same trials* (common random numbers), so the before/after delta is the cut's own
  effect: never negative, and exactly 0 for a cut no route crosses. `riskReduction` is the drop in
  P(any sensitive asset compromised); `expectedReduction` the drop in the expected number
  compromised, which keeps moving when one asset open to anyone pins the first at 100%. Pairs with
  the choke-point optimizer: "if we fix these N edges, residual risk drops from X to Y".

Exposed as the GraphQL `kShortestPaths`, `riskSimulation` and `whatIf` queries.

## Honest probabilities: provenance, not false precision

A CISO who asks "why 58%?" deserves better than "we multiplied some estimates".
Every edge weight now declares **where it came from**, and every path a
**confidence band** built from that provenance:

- **kev / epss / runtime** - evidence: observed exploitation (CISA KEV), a
  data-driven prediction (FIRST EPSS), or a live Falco runtime alert.
- **cvss / severity / heuristic** - estimate: a CVSS-anchored guess, a bare
  severity label, or an assumed topology/identity default.

> **Known input caveat (the kind calibration is built to surface):** EPSS is a
> *marginal* probability - P(any exploitation activity in the wild within 30 days) -
> not the conditional P(an attacker traverses *this* edge in *this* environment) the
> score needs. It's a global base rate (usually small), so taking it as `p(e)` tends
> to *understate* a present attacker. We feed it as-is on purpose and let the
> calibration loop reveal/correct the bias on real verdicts (rather than transforming
> it on a hunch); the `severity → p` anchors (0.9/0.7/0.4/0.2) are deliberate
> heuristics too, which is why they carry low-confidence bases. See
> [`internal/threatintel`](../../backend/internal/threatintel) and `internal/ingestion/severity.go`.

Each hop in the kill chain is tagged (**KEV**/**runtime** green, **default weight** grey)
and, when it is something an attacker does, mapped to a **MITRE ATT&CK technique + tactic**
(`T1190 · Initial Access`, clickable to the ATT&CK page) - so a probability-ranked route
reads as a recognizable kill chain a defender can map to detections and controls. The
technique is read in the route's context: initial access is credited to the hop where
access is gained (the exploit when the route has one, the exposure otherwise), and an
exploit after the attacker is already inside is lateral movement (T1210). Facts about
software - an image that ships a library, a library that has a CVE - carry none, and IAM
privilege escalation is T1098.003 (additional cloud roles). The path also carries `confidence` + a `confidenceLabel`
(**high / medium / low**)
- the mean trustworthiness of its hops. So *"58%, **low confidence** - rests
mostly on severity heuristics, here are the assumed hops to validate"* replaces a
falsely-precise number. A path resting on a KEV CVE and a runtime alert reads as
**high confidence** even at the same score as an all-heuristic one. The score
itself is unchanged - what's added is the honesty about how much to trust it.

The same honesty applies to the **independence assumption** baked into `∏p`: the
product treats every hop as independent, which understates the risk when several
hops share a common cause (one weakness gating multiple steps). So each path also
carries `scoreUpperBound` - the weakest hop, `min p`, the score if the hops are
perfectly correlated - and a `correlatedHops` flag when two or more hops rest on
the same weight basis. The real exploitability lives in **`[score, scoreUpperBound]`**,
and the UI shows *"↑ up to X% if correlated"* instead of pretending the point
estimate is exact.

There is a second, orthogonal uncertainty: not *"are the hops correlated?"* but
*"how well do we even know each `p`?"*. So each edge's probability is treated as a
**Beta posterior** whose width is set by its evidence - tight for a KEV/runtime hop,
wide for a heuristic guess - and propagated through the product to a **90% credible
interval** on the score (`scoreCiLow`/`scoreCiHigh`, the UI's *"90% CI 39-71%"*).
The same per-edge posteriors feed the Monte Carlo headline: instead of a flat ±30%
"sensitivity" wiggle, the band is now an outer epistemic loop that resamples every
edge from its posterior, so *"modeled X-Y%"* is the spread the evidence justifies.
Point estimates are unchanged; what's quantified is how far they could honestly move.

Finally, the deepest fix: `∏p`'s independence assumption is wrong because attack
steps are correlated through a latent variable - **the attacker's capability**. So
the score is also marginalized over a small set of **attacker profiles** (commodity
/ criminal / APT), each with a threat-model prior `P(c)` and a skill that shifts each
hop's odds by how much it actually depends on skill (a public KEV exploit barely, a
heuristic topology guess a lot): `S(P) = Σ P(c)·∏ p(e|c)`. *Within* a profile the
independence is honest; *marginalizing* reintroduces the positive correlation the bare
product drops. The profiles are anchored so that, averaged, they give back each hop's own
probability: the mixture changes the correlation and nothing else, and reads between the
naive score and the weakest hop. The payoff is the per-profile breakdown a SOC triages on -
*"72% vs an APT, 18% vs commodity"* - surfaced on each path. Retune the priors to
your own threat model with `ATTACKER_PROFILE_PRIORS` (the naive score is kept as the
independent baseline; the mixture is the sharper lens on top).

## Triage priority: what to fix first, not 500 findings

A 2-person security team can't act on every reachable path. The raw exploit score
answers *how easy*; it doesn't answer *how much should I care*. So each path also
gets a composite **triage priority** (0–100, banded **P1 / P2 / P3**) that blends
the signals an analyst actually weighs:

- exploitability (`score`) and how much to trust it (`confidence`),
- **runtime-confirmed** (a live Falco alert - it's not theoretical, it's happening), or
  **open to anyone** (a direct-access path: the asset is readable now, weighted like a live alert),
- a **KEV** weakness anywhere on the route (known-exploited in the wild),
- **target sensitivity** (a classified-PII sensitive asset outranks a name-heuristic guess),
- **blast radius** (an internet entry that opens many paths is higher leverage).

Paths come back **priority-first**, so `attackPaths(limit:5)` *is* the "fix these
today" list, and every priority is **explainable** - it carries the factors
(`"runtime-confirmed (active)"`, `"KEV on path"`, `"classified PII target"`,
`"entry shared by 4 paths"`) rather than a black-box rank. The effect is the
honest re-ranking you want: a **runtime-confirmed path to PII at 36%** outranks an
**uncorroborated 90%** one. (Weights and bands are documented and tunable.)

**A fact about the route makes it P1**, whatever the blend says - the blend weighs
exploitability at a third, and alone it could not put a live attack into
AdministratorAccess above P2. The facts: a **runtime alert** on the route; an asset **open
to anyone**; a **KEV** weakness on a route an attacker is likely (≥ 50%) to complete; or a
route that is likely (≥ 80%), on evidence rather than default weights, into a
high-value (not name-inferred) asset. `priorityReason` says which, in one sentence. Inside
P1 the order is kept: every P1 path sits at 70 plus 30% of its blend.

**Red-team and BAS verdicts re-band a path where paths are listed**: one a tester walked
end to end is P1; one a tester could not walk drops to P3 - unless a runtime alert fired on
it or it is open to anyone, which a failed test does not undo: that path stays and says
the **evidence conflicts**. The analyzer's own Priority never contains a verdict: it is
what the next verdict records and the triage order is graded against
(`priorityDiscrimination`), and a ranking a verdict already moved would grade itself.

**The dashboard lists the same order one asset at a time.** Routes are grouped under the
sensitive asset they reach - "cluster-admin, 4 routes" rather than four rows that look
unrelated - and a group sits where its most urgent route sits, so reading the groups top to
bottom is reading the engine's order. Routes a tester refuted (with no runtime alert or open
access to contradict the test) are set apart in a closed **Refuted by tests** section: they
are candidates to suppress as false positives, not work still to do.

**Every route has a link**: `#paths/<path id>` opens the dashboard on it, and **Copy link** in
the detail puts that link on the clipboard for a ticket or a chat. Path ids are derived from
the route itself, so a link stays good while the route stays open; one whose route has since
closed - fixed, or outside the application scope shown - says so instead of quietly showing
another route.

## Quantified risk, what-if & compliance export

A path score answers "how exploitable is *this* route". Boards and auditors ask
harder questions, and PerspectiveGraph answers them:

- **Monte Carlo risk quantification** (`riskSimulation`) - each trial realizes
  every edge independently, then checks sensitive-asset reachability. Over thousands
  of trials it estimates **P(sensitive asset compromised)** with a 95% confidence
  interval, plus **P(at least one sensitive asset compromised)** and the expected
  number that fall. Unlike `∏p`, it accounts for the many routes that share edges
  - in the demo, *P(account compromise) ≈ 1.0, ~5 sensitive assets expected to fall*.
  The headline is honest about its own uncertainty: alongside the sampling CI it
  reports a **credible band** (the answer when each edge's probability is redrawn
  from its Beta posterior - wide for guesses, tight for evidence), shown as
  *“modeled X–Y%”* - a tight band means trust the number, a wide one means treat it
  qualitatively.
- **K-shortest paths** (`kShortestPaths`) - Yen's algorithm lists the top-K routes
  to a sensitive asset, so you see the near-best alternates a single edge-cut would
  leave standing.
- **What-if simulation** (`whatIf`) - propose a set of edges to cut and get the
  surviving paths and the **residual risk** (before → after, with enough trials
  to make the delta meaningful): *"cut this edge → account compromise 100% →
  99.9%, 11 paths remain"*. Available right in the dashboard: hit **“what-if”**
  on any hop of a kill chain to simulate cutting it.
- **OSCAL compliance export** - `GET /export/oscal` renders the posture as a NIST
  **OSCAL 1.1.2 assessment-results** document: each attack path becomes an
  observation + risk, and each undermined **NIST 800-53 control** (SC-7, AC-6,
  RA-5, SI-2, AC-2 for IAM privesc, SI-4/IR-4 when runtime-confirmed, …) a
  not-satisfied finding - the language GRC tooling and auditors actually consume.

Both exports - OSCAL and the SIEM NDJSON enrichment feed - download straight from
the dashboard's **Export** menu in the top bar, or over HTTP:

```bash
curl -s "$API/export/oscal" > oscal.json   # NIST OSCAL assessment-results
```
