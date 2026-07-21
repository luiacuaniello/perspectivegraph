# Red-team calibration lab (scaffold)

This is the randomized AWS environment that feeds the calibration oracle
([`backend/internal/redteam`](../../backend/internal/redteam)). It is a **scaffold**:
the dimensions and safety rails are specified here, but no resources are applied until
you deliberately wire and run it against a dedicated lab account. Nothing in the repo
touches AWS on its own.

## Why it exists

The engine's per-edge probabilities are expert priors, not fitted numbers. The only
honest way to calibrate them is to pair each prediction with an outcome decided by an
authority **independent of the engine** - AWS itself. This lab manufactures that
independence: it stands up environments whose ground truth the engine cannot see, the
engine scores the paths, the oracle attempts them, and reality (an SCP, a permission
boundary, an IMDSv2 posture, a private subnet) answers confirmed or refuted.

The loop, proven end-to-end on fixtures in `internal/redteam`:

```
randomized lab  ─▶  ingest  ─▶  engine scores paths  ─▶  oracle attempts each
      ▲                                                          │
      └──────────  calibration flywheel  ◀── refuted/confirmed ──┘
                   (internal/validation)
```

## Randomization dimensions

The point is variety the engine cannot anticipate, concentrated on the axes the
engine deliberately does **not** evaluate (so refutations arise naturally):

| Dimension | Values | Which engine assumption it stresses |
|---|---|---|
| IMDS posture | `v1-optional` / `v2-required` | the ASSUMES hop probability (0.9 vs 0.6) |
| SCP on the OU | none / `deny iam:*` / `deny outside region` | privesc edges the engine can't see |
| Permission boundary | none / caps to read-only | escalation the engine over-reports |
| Condition keys | none / `aws:SourceIp` / `aws:MultiFactorAuthPresent` | Allow treated as unconditional |
| Resource scoping | `*` / single-resource | the `resource_scoped` lower-probability edge |
| Subnet placement | public (igw) / private (nat) | reachability precision |
| Real privesc primitive | present / absent | true-positive vs clean control |

Each `terraform apply` with a fresh random seed yields one labelled environment.

## Intended layout (to build)

- `variables.tf` - the knobs above (present as a documented scaffold).
- `main.tf` - the VPC + EC2 + IAM the knobs parameterize. **Not committed**: it is the
  AWS-touching part, authored when you run the lab.
- `outputs.tf` - the ground-truth manifest (which paths *should* be exploitable given
  the randomized reality) plus the ingest bundle, so a run is self-describing.

## Workflow (when you run it)

```
terraform apply -var seed=$RANDOM              # one randomized lab in a DISPOSABLE account
# ingest the lab into a local PerspectiveGraph, let the engine score paths
perspectivegraph redteam --oracle aws --tenant lab   # attempt each path, post verdicts
terraform destroy                              # tear it down immediately
```

The verdicts land in the calibration store and move Brier / ECE / the recommended
scale, exactly as `TestClosesTheFlywheelLoop` demonstrates on fixtures.

## Safety rails (non-negotiable)

- **Dedicated, disposable account only.** The oracle exercises admin-equivalent
  escalations to observe whether AWS permits them; it must never run near anything
  real. Use an account with a hard budget alarm and nothing else in it.
- **Destroy immediately.** Labs are ephemeral; leaving one running is both cost and
  exposure.
- **The oracle is read-mostly by design.** IAM claims are settled with
  `iam:SimulatePrincipalPolicy` (a dry-run evaluator that changes nothing) wherever
  possible; only where a simulation is insufficient does it perform a real
  `sts:AssumeRole`, and it never uses the assumed credentials for anything.
- **Distribution shift is a known limitation.** A calibration fitted on synthetic labs
  may not transfer to a real customer estate. Read the *per-score-bucket* reliability
  (does "0.8" fire ~80% of the time?), not just the marginal base rate, which is the
  least transferable part.
