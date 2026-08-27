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
- **It does not replace a CNAPP.** It answers the reachable-path question inside the
  developer workflow; it is not a scanner, an inventory or a compliance product.
- **Coverage is not the strength.** Cartography has more connectors, BloodHound
  defined the category, PMapper does IAM privilege escalation, KubeHound does
  Kubernetes paths. The claim is the cross-domain route and the honesty about the
  number, not breadth.

Two words never to use: "calibrated" without a "not" in front of it, and any
comparison that positions this against a commercial CNAPP on coverage. Both invite
a check the project loses.


## Verifying the claims

None of the above asks to be taken on trust:

```bash
make test              # backend + frontend suites
make bench-cloudgoat   # precision/recall against known-vulnerable scenarios
cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd backend && go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude=G104 ./...
```
