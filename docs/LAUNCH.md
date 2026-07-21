# How this project is described

The engine reports its own calibration because a claim you can check beats one you
have to accept. The way the project is talked about should follow the same rule.

This is the working copy for that: what is claimed, what is deliberately not, and
the announcement drafts. It is in the repository rather than a private doc on
purpose - if the pitch cannot survive being read by the people it is aimed at, it
is the wrong pitch.

## What is claimed

- Findings from tools you already run, correlated into **one route across domains**:
  network, identity, supply chain and runtime in the same chain.
- Each route carries **where its confidence comes from** - which hops are observed
  evidence and which are estimates - and a **calibration verdict** against recorded
  outcomes.
- The engine is **deterministic and reproducible**, which is what makes it worth
  handing to an agent instead of asking a model to imagine routes.
- Everything above is **verifiable in one command**, not asserted.

## What is not claimed

State these before anyone has to find them. They are in the README's maturity
section for the same reason.

- **The scores are not field-calibrated.** They are expert estimates. What ships is
  the instrument to calibrate them against your environment, not a universal
  constant - which does not exist, since exploitability depends on the environment.
- **One cloud is genuinely connected.** AWS is live; Azure is fixtures only; there
  is no GCP connector and no AWS Organizations multi-account ingestion.
- **It does not replace a CNAPP.** It answers the reachable-path question inside the
  developer workflow; it is not a scanner, an inventory or a compliance product.
- **Coverage is not the strength.** Cartography has more connectors, BloodHound
  defined the category, PMapper does IAM privilege escalation, KubeHound does
  Kubernetes paths. The claim is the cross-domain route and the honesty about the
  number, not breadth.

Two words never to use: "calibrated" without a "not" in front of it, and any
comparison that positions this against a commercial CNAPP on coverage. Both invite
a check the project loses.

## Where

Ordered by leverage, and posted in sequence rather than all at once: the first one
is single-shot, and if the framing is wrong it is better to learn that before
spending the rest.

| Venue | Framing that fits | Note |
|---|---|---|
| Hacker News (Show HN) | the honesty angle | one shot, no reposting; be in the thread for the first hours |
| MCP ecosystem (registries, awesome lists, agent communities) | the deterministic-tool angle | far less crowded; lowest friction to try |
| r/netsec | the cross-domain correlation | strict moderation, exactly the right audience |
| awesome-* lists (security, devsecops, mcp-servers) | a one-line entry | no spike, but it compounds |

## Drafts

### Show HN

> **Show HN: PerspectiveGraph - attack-path analysis that tells you how much to trust its own scores**
>
> I spent the last months building a cloud attack-path engine. It correlates the
> output of scanners you already run (Trivy, Semgrep, Falco, Kubernetes dumps, IAM)
> into one graph, and finds the routes that go from internet exposure to something
> worth stealing.
>
> The idea is not new: Cartography builds the graph, PMapper does IAM privilege
> escalation, BloodHound defined the category, KubeHound does Kubernetes paths. Two
> things I did not find elsewhere:
>
> **A route crosses domains.** Network, identity, supply chain and runtime in the
> same chain - `edge-alb → container → image → log4j → CVE-2021-44228 → admin IAM
> role`. The existing tools each cover a slice; stitching them is the work.
>
> **The engine measures how wrong it is.** Every route has a score, but also an
> uncertainty band, the provenance of each hop (observed evidence versus estimate),
> and a calibration verdict against recorded outcomes. When the model is too sure of
> itself, the dashboard says "overconfident" next to the number.
>
> Which forces me to be clear: **the scores are not field-calibrated.** They are
> expert estimates. What the engine gives you is the instrument to calibrate them
> against your own environment, not a universal constant - there isn't one.
>
> Other limits, before you find them: one cloud is genuinely connected (AWS; Azure is
> fixtures only), no GCP, no multi-account Organizations.
>
> It speaks MCP, so an agent can query it instead of inventing routes. The tool worth
> the integration is `simulate_fix`: it re-runs the simulation with the edges you name
> cut, and reports what actually changes rather than estimating it.
>
> `make demo` shows it in 90 seconds. Apache 2.0.

### MCP ecosystem

> A language model cannot reliably enumerate fourteen thousand edges, does not run
> Dijkstra, and asked for "the attack paths in my account" will produce plausible
> routes that do not exist.
>
> So I exposed a deterministic attack-path engine over MCP. Eight tools; the one
> worth integrating is `simulate_fix`, which re-runs the whole simulation with the
> edges you name removed and reports what actually changes.
>
> The surface is **read-only** on purpose - an agent that can silently mark a risk as
> accepted is a liability, not a feature. And the tool descriptions tell the model
> the scores are expert estimates and to call `get_score_trust` before quoting one as
> a probability, because a description is the one place a caveat propagates: the
> model rereads it every call.

### r/netsec

Lead with the correlation and the benchmark, not the pitch: that audience reads
tools, not announcements. Open with the kill chain the demo prints, say which of
its hops are evidence and which are heuristics, and link the CI-gated
precision/recall battery in `backend/testdata/cloudgoat`.

## Questions worth answering honestly

**"How is this different from Cartography or BloodHound?"** They are better at what
they do. Cartography builds a broader graph and does not score paths; BloodHound is
identity-centric; PMapper is IAM-only; KubeHound is Kubernetes-only. The difference
is one route across all of those domains, plus the uncertainty reporting. Say it
plainly; the answer is in the post so nobody has to ask first.

**"Are the probabilities meaningful?"** Not yet as absolute values - as a ranking.
That is what the Trust page exists to tell you, per environment.

**"It says it was written with AI."** Yes, and it is in the README. The gates are
reproducible: `make test`, `make bench-cloudgoat`, `govulncheck ./...`,
`gosec ./...`. Judge it on those.

## Before posting

The front door has to hold, because a good post that leads to a broken first five
minutes is worse than no post.

```bash
docker compose --profile app down -v      # start from nothing
make demo                                 # must print a path and its fix
make test && make bench-cloudgoat         # must be green
```
