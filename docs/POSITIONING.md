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


## Verifying the claims

None of the above asks to be taken on trust:

```bash
make test              # backend + frontend suites
make bench-cloudgoat   # precision/recall against known-vulnerable scenarios
cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd backend && go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude=G104 ./...
```
