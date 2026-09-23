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
- **The ranking has an instrument, not a result.** The order an operator works through is
  now graded - AUC over confirmed and refuted verdicts, for S(P) and for Priority - but no
  field dataset has been fed to it, so on a real install it reads `insufficient-data`.
  See *Three questions, three measurements* below for why that is a third claim and not a
  restatement of the other two.
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
list, and what the number attached to it means. They fail independently, and each needs
its own measurement.

**Detection - is a surfaced path real, and did we miss any?** Measured as precision and
recall. `make bench-cloudgoat` grades the engine against scenarios whose paths are
declared in advance, negative cases included; `validation.Metrics` does the same over
the subset a red team or a BAS platform actually tested. Neither is a global
precision/recall claim - that needs exhaustive ground truth, which nobody has - and
both say so.

**Discrimination - are the dangerous paths above the less dangerous ones?** Measured as
AUC: the probability that a confirmed path outranks a refuted one, ties counted half, so
0.5 is a coin and 1 is perfect separation. It is rank-based, which is what lets it grade
two things calibration cannot. The first is the score itself. The second is `Priority`,
the order `attackPaths(limit: N)` returns and an operator actually works down - which is
not a probability at all, so no Brier score could ever say anything about it. For that,
each verdict now records the Priority its path had when it was recorded, captured
server-side like S(P). The report carries an approximate 95% interval and a verdict -
`discriminates`, `indistinguishable-from-chance`, `inverted` - withheld below ten of each
class, and `Partial` verdicts are excluded because half credit is not a class.

Three things the number does not say. A modest Priority AUC is partly by design: Priority
weighs target sensitivity and blast radius on purpose, so a refuted path to a crown jewel
ranking high is the order doing its job, not failing at it. The synthetic self-test
(`make seed-validation`) shows the separation cleanly - its `overconfident` scenario is
badly miscalibrated and orders paths *better* than any other, while `low-resolution`
cannot be told apart from a coin - but those verdicts are generated, and prove the
instrument rather than the engine. And the gate diagnosis takes its claims about order
from this measure rather than inferring them: it says "the ranking is sound" only on a
`discriminates` verdict and quotes the AUC beside it, reads an order indistinguishable
from chance as low-resolution, names an inverted one, and says the ranking is not yet
graded when there are too few of a class. On the synthetic scenarios this changed no
scenario's recommendation, only what each is allowed to claim about order.

**Calibration - when the engine says 0.8, does it happen about 80% of the time?**
Measured as Brier score, log loss, ECE and a reliability diagram, over verdicts that
reality actually settled. Below `minCalibrationSamples` the verdict is
`insufficient-data` and no rescaling is offered, because a thin sample fits noise.
`well-calibrated` needs the reliability bins to agree as well as the averages; when only
the mean matches the verdict is `calibrated-on-average`, which licenses no statement about
what any particular score means - a score that orders nothing can match the base rate on
average, and used to be called well-calibrated for it. An
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
the store is small. And the exploitation lab specified in `deploy/redteam-lab` will need its
own separation once it is built: if the scenarios that shape the heuristics are the
scenarios that get exploited, the resulting calibration measures the fit, not the model.

## Verifying the claims

None of the above asks to be taken on trust. Note which question each command answers:

```bash
make test              # the Go suites (the dashboard's: cd frontend && npm test)
make bench-cloudgoat   # DETECTION: precision/recall against known-vulnerable scenarios
make seed-validation   # CALIBRATION + DISCRIMINATION on synthetic verdicts - proves the instrument, not the engine
cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd backend && go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude=G104 ./...
```
