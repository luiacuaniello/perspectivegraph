# Positioning

How this project is described - in the README, in an issue, in a talk, in a post.

The engine reports its own calibration because a claim you can check beats one you
have to accept. The way the project is talked about holds to the same rule: the
limits below are stated before anyone has to find them, and every claim above them
is verifiable in one command.

This is for contributors as much as for the maintainer. If you describe
PerspectiveGraph somewhere, this is the shape of the honest version.

## What is claimed

- Findings from tools you already run, correlated into **one route across domains**:
  network, identity, supply chain and runtime in the same chain.
- Each route carries **where its confidence comes from** - which hops are observed
  evidence and which are estimates - and a **calibration verdict** against recorded
  outcomes.
- The engine is **deterministic and reproducible**, which is what makes it worth
  handing to an agent instead of asking a model to imagine routes.
- Everything above is **verifiable in one command**, not asserted.

## Where this sits

Someone will ask what this replaces. The answer is three questions, and none of them
needs another product's name to answer - describe the shape precisely enough and the
reader places it themselves.

**Does it replace the tools I run?** No. It consumes them. The graph is built from the
output of scanners already in the pipeline, so the value appears without another agent,
another scan window, or another thing to keep running. A tool that competes with your
scanners has to win on detection; this one has to win on what it does with what they
already found, which is a different job.

**When does it act?** At the pull request, before the merge - which is the whole point,
and the sharpest line to draw. Reachability answered after deployment produces a ticket;
answered at review it produces a diff that never lands. The engine also runs
continuously against the live graph, but the wedge is the merge gate, and a product that
can only tell you about production is answering a later question.

**Why believe the number?** Because it grades itself. Each route carries which of its
hops are observed evidence and which are estimates, and the calibration report says
whether the scores held up against recorded outcomes - including saying "insufficient
data" and withholding a verdict when nothing has been tested. The distinguishing claim
is not accuracy; it is that the accuracy is measured and published, so a wrong number is
visible rather than merely wrong.

What it therefore sits *beside* rather than *instead of*: the scanners that find things,
the inventory that lists them, the runtime that watches them. What it sits *in front of*
is the merge.

## What is not claimed

State these before anyone has to find them. They are in the README's maturity
section for the same reason.

- **The scores are not field-calibrated.** They are expert estimates. What ships is
  the instrument to calibrate them against your environment, not a universal
  constant - which does not exist, since exploitability depends on the environment.
- **One cloud is genuinely connected.** AWS is live; Azure is fixtures only; there is
  no GCP connector. Several AWS *accounts* can be pulled in one pass and are kept
  distinct, but that has been exercised on fixtures, not yet against real accounts, and
  the accounts are listed rather than discovered - there is no AWS Organizations
  integration and no SCP evaluation.
- **The ranking is not graded.** Detection is measured and calibration is measured; the
  ordering that decides which path an operator opens first is not. See *Three questions,
  three measurements* below for why those are three claims and not one.
- **It does not replace a CNAPP.** It answers the reachable-path question inside the
  developer workflow; it is not a scanner, an inventory or a compliance product.
- **Coverage is not the strength.** Cartography has more connectors, BloodHound
  defined the category, PMapper does IAM privilege escalation, KubeHound does
  Kubernetes paths. The claim is the cross-domain route and the honesty about the
  number, not breadth.

Two words never to use: "calibrated" without a "not" in front of it, and any
comparison that positions this against a commercial CNAPP on coverage. Both invite
a check the project loses.


## Three questions, three measurements

A surfaced path carries three separate claims: that it exists, where it sits in the
list, and what the number attached to it means. They fail independently, and only two
of them are measured here.

**Detection - is a surfaced path real, and did we miss any?** Measured as precision and
recall. `make bench-cloudgoat` grades the engine against scenarios whose paths are
declared in advance, negative cases included; `validation.Metrics` does the same over
the subset a red team or a BAS platform actually tested. Neither is a global
precision/recall claim - that needs exhaustive ground truth, which nobody has - and
both say so.

**Discrimination - are the dangerous paths above the less dangerous ones?** *No metric is
computed.* The engine nevertheless ranks: every path gets a composite priority and a
P1/P2/P3 band, and `attackPaths(limit: N)` returns the top N, so that ordering decides
what an operator looks at first. Nothing grades that ordering. The closest thing in the
codebase is the edge track's reliability diagram, which is deliberately kept for exactly
this read - whether higher-scored CVEs really do enter KEV more often - but it speaks to
per-CVE hop probabilities, not to the path order a team works through, and it is a shape
to eyeball rather than a number. A model can order perfectly while every number it prints
is wrong, or be honest about each number and still bury the path that matters at position
forty; precision/recall answers neither question, and neither does a Brier score. This is
a gap, and it is written here rather than left for someone else to find.

**Calibration - when the engine says 0.8, does it happen about 80% of the time?**
Measured as Brier score, log loss, ECE and a reliability diagram, over verdicts that
reality actually settled. Below `minCalibrationSamples` the verdict is
`insufficient-data` and no rescaling is offered, because a thin sample fits noise. An
unmeasured outcome is excluded rather than imputed: `CalibrationGrade` admits only
Confirmed and Refuted, since the most common path shape contains a hop no API can
settle - whether an attacker gets code execution on the exposed host.

None of the three can be read off the others, and a number is only measurable once the
quantity behind it is named - which is the next section.

## What a score is the probability of

A probability with no trial behind it is not a frequency, so the quantity has to be
stated. Each hop carries `p(e)`, an exploit probability whose provenance is recorded
(`kev | epss | runtime | cvss | severity | heuristic`). An attacker profile `c` shifts it
by capability, scaled by how much that hop depends on skill at all:

    p(e|c) = sigmoid( logit p(e) + skill(c)·sensitivity(basis(e)) )
    S_c(P) = ∏ p(e|c)
    S(P)   = Σ_c P(c)·S_c(P)

A path score is therefore: **the probability that this route can be traversed end to
end, by an attacker of the mixture's capability, starting from an internet-exposed seed,
in the environment as it was observed - given that the route is attempted.**

Three things it deliberately is not:

- **Not per unit of time.** There is no horizon in the model - no per-year rate, no
  arrival process. `0.8` does not mean "80% likely this year"; the model has nothing to
  say about when, or how often anyone tries.
- **Not conditional on being attacked.** It is conditional on the route being *attempted*.
  A route nobody touches is never traversed, and its observed frequency would be zero
  however open it is. That conditioning is what makes the number measurable in a lab -
  where every route is attempted by construction - and it is exactly why it must not be
  read as a breach likelihood for an organisation.
- **Not a statement about the whole environment.** `S(P)` grades one route. The Monte
  Carlo layer answers a different question - P(any crown jewel reachable from any
  internet seed), correlations and shared edges included - and it is neither the sum nor
  the product of the path scores.

And there is more than one number, so a measurement has to say which one it grades:
`Score` (the naive ∏p baseline), `MixtureScore` and `ProfileScores` (the
correlation-aware lens), `PosteriorMean` with its credible band (the epistemic
counterpart), `Priority` in [0,100] (the triage axis, which blends corroboration and
target sensitivity and is *not* a probability at all), and the environment-level
compromise probability. A verdict's `Scope` fixes which quantity the calibration grades
it against; a calibration report that does not name the quantity is not a measurement.

## Keeping the measurement out of the model

A calibration that grades a model against its own inputs reports an excellent number and
means nothing. Four separations keep that from happening, and they are structural rather
than procedural - there is no step anyone has to remember.

- **Verdicts never re-enter scoring.** `internal/analyzer` does not import
  `internal/validation` at all. A recorded outcome cannot move an edge probability, so
  the next verdict grades the same model that produced the last one.
- **The suggested corrections are published, not applied.** `RecommendedScale` and the
  per-basis Platt correction are reported as diagnostics; nothing multiplies a score by
  them. On a thin sample, silently rescaling is fitting noise - and it would also make
  every later verdict circular.
- **The recalibrated Brier is cross-validated.** `BrierRecalibratedByBasis` is fitted and
  scored under k-fold with a deterministic split, so a correction cannot flatter itself
  on the bucket it was fitted to. Below the fold threshold it falls back to in-sample and
  says so - which is the honest label, not a solved problem, and on a small store it is
  the common case.
- **The KEV track breaks a circle with time.** A CVE in KEV is assigned its probability
  *by the formula that reads KEV*, so grading against KEV membership today would score
  the formula against its own input. `internal/kevholdout` seals a forecast for a CVE
  that is *not* in KEV at that moment and grades it only after a window, against an event
  that had not happened when the forecast was made - the construction FIRST uses to
  evaluate EPSS.

The three tracks are also never merged: path-scoped, target-scoped and edge-scoped
verdicts grade different events, and pooling them would bias the report.

Two residues are open rather than closed. The in-sample fallback above is real whenever
the store is small. And the lab that Milestone 3 builds will need its own separation: if
the scenarios that shape the heuristics are the scenarios that get exploited, the
resulting calibration measures the fit, not the model.

## Verifying the claims

None of the above asks to be taken on trust. Note which question each command answers -
none of them grades the ranking:

```bash
make test              # backend + frontend suites
make bench-cloudgoat   # DETECTION: precision/recall against known-vulnerable scenarios
cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd backend && go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude=G104 ./...
```
