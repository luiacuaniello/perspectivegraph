# Concepts in plain words

*Part of the [PerspectiveGraph manual](../MANUAL.md).* The words the dashboard and these pages use,
each in a few sentences, with a link to where it is explained in full. Read this first if the rest of
the manual assumes too much.

## The picture

**Graph.** Everything the engine knows about your environment, joined up. Assets, identities and
findings are the nodes: a load balancer, a container, an IAM role, a CVE. What connects them are the
edges: the load balancer *exposes* the container, the container *assumes* the role, the CVE
*affects* the image. It is built from what you already run - scanners such as Trivy and Semgrep, and
your cloud and Kubernetes state - not from an agent of its own.
[How it works](how-it-works.md#the-core-idea)

**Entry point.** Where an attacker starts. By default, anything reachable from the internet. An
optional second lens also starts from IAM users, on the premise that a long-lived key can leak; the
routes it finds are marked as credential-origin, so the two stories stay apart.
[Seed origin](how-it-works.md#the-core-idea)

**Sensitive asset.** What is worth stealing: a database of customer data, an administrator role, a
secrets store. An asset is sensitive when a classifier says so (Macie, a DLP tool, a tag policy), or
when its name strongly suggests it - and then the dashboard says *inferred*, so the guess can be
checked. [Topology discovery](integrations.md#topology-discovery-no-hand-stitched-ids)

**Route.** A chain of steps from an entry point to a sensitive asset: the attack path. The dashboard
says *route*; the API and parts of this manual say *attack path*. They are the same thing.

**Hop.** One step of a route - one edge - with the probability that an attacker gets across it and
the evidence that probability rests on.

**Open to anyone.** A sensitive asset that needs no route at all: a bucket anyone can read, a role
anyone may assume. It is listed as a route with no hops and a score of 100%, and it is always P1.
[Direct access](how-it-works.md#the-core-idea)

## The numbers

**Score.** The probability that the route can be walked end to end, by an attacker of mixed
capability, starting from its entry point, in the environment as it was observed - *given that
someone tries*. It is not "likely to happen this year", and it has not been measured against real
attacks yet: until outcomes are recorded, it is the model's estimate.
[What a score is the probability of](../POSITIONING.md#what-a-score-is-the-probability-of)

**Evidence and estimates.** Every hop says where its probability came from. *Evidence* is something
observed: the CVE is in CISA's catalogue of exploited vulnerabilities (KEV), FIRST's EPSS forecast
scores it, or a runtime alert fired on it. An *estimate* is derived: from a CVSS score, a bare
severity, or an assumed default for that kind of connection.
[Provenance](scoring.md#honest-probabilities-provenance-not-false-precision)

**Confidence.** How much of a route rests on evidence rather than estimates - high, medium or low.
Two routes at the same score can deserve very different trust.

**90% interval.** The range the score could reasonably move within, given how well each hop is
known. Narrow where the hops rest on evidence, wide where they are estimates. A wide interval is not
a flaw in the number; it is the number being honest about itself.
[Risk scoring](scoring.md#risk-scoring)

**Priority (P1, P2, P3).** What to fix first. It weighs the score and its confidence together with a
runtime alert on the route, a known-exploited CVE, how sensitive the target is, and how many routes
share the same entry. Some facts make a route P1 whatever the arithmetic says - a live alert, an
asset open to anyone - and every route says in one sentence why it sits where it does.
[Triage priority](scoring.md#triage-priority-what-to-fix-first-not-500-findings)

## Acting on it

**Merge gate.** The check on a pull request. It answers one of three things: *clean* (analysed, opens
no route), *blocked* (opens or worsens a route, and names it), or *unknown* - nobody analysed this
change, because a scan or an upload went wrong. Unknown fails the build by default, so a broken
pipeline cannot pass as a clean one.
[The merge gate](ci-gate.md#the-merge-gate-github-action-cli-and-trivy-plugin)

**Fix.** A ready-to-apply change that cuts one hop of a route: a Kubernetes NetworkPolicy, a
Terraform change, an IAM policy. It can be opened as its own pull request, so it arrives as something
to review, not something to copy.
[Remediation as a pull request](ci-gate.md#the-wedge-attack-paths-in-your-pull-request)

**Choke point.** A hop that many routes share. Fixing it closes all of them at once, so the list of
fixes is ranked by how much risk each removes, not by how many findings it touches.
[Choke points](working-the-findings.md#choke-point-remediation-optimizer)

**What-if.** Try a fix before making it: cut a hop in the dashboard and see which routes close and how
much risk is left. [What-if](scoring.md#quantified-risk-what-if--compliance-export)

**Suppression.** Taking a route off the board on purpose - accepted risk, false positive, a
mitigating control, a duplicate - with a named owner, a note and, if you want, an expiry after which
it comes back. [Triage and suppression](working-the-findings.md#triage--suppression-close-the-false-positive-loop)

## Trusting it

**Outcome.** The result of someone actually testing a route: a red team, a breach-and-attack
simulation tool, a pentester. *Proven* (walked end to end), *refuted* (could not be walked), *partly
walked*, or *missed* - a real route the tester found that the engine never showed, the one error that
never surfaces on its own. [Recording outcomes](accuracy.md#validated-against-reality-precision--recall)

**Calibration.** Whether the scores mean what they say: of the routes scored around 70%, did about 70%
turn out walkable? It needs recorded outcomes. With none, the Accuracy page says so and shows the
predictions waiting to be graded; under thirty, it gives a direction, not a verdict.
[Calibration](accuracy.md#calibration-does-the-score-mean-anything-the-demoproduction-gate)

**Ranking.** Whether the order is right even where the probabilities are off: do the routes that
turned out real sit above the ones that were refuted? A model can be wrong about the level and still
put the right routes first, and that is the part triage depends on.
[Discrimination](accuracy.md#discrimination-does-the-order-mean-anything)

**Precision and recall.** Of the routes that were tested, how many were real (precision); of the real
routes testers found, how many the engine had shown (recall). Both are about what was tested, never a
claim about the whole estate. [Validated against reality](accuracy.md#validated-against-reality-precision--recall)
