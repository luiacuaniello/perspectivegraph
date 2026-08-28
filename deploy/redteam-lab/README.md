# Red-team calibration lab (specification)

This directory is a **specification, not runnable Terraform**. It describes the
randomized AWS environment that would settle the last calibration question the project
cannot answer for free. There is no `main.tf`, and `variables.tf.example` provisions
nothing - it is named that way so nobody mistakes it for infrastructure. Nothing in this
repository touches AWS on its own.

## Read this first: most of it is already free

When this was written, the premise was that refuting the engine required standing up
deliberately vulnerable environments. That turned out to be mostly wrong. AWS's own
policy evaluator, `iam:SimulatePrincipalPolicy`, is a **dry run**: it answers "would this
be allowed" while applying the SCPs, permission boundaries and condition keys the
engine's own reader skips - for free, creating nothing, with no exploitable
infrastructure anywhere. Two of the axes below already have working labs that cost
nothing, and one of them found a real bug.

So the honest status of the seven randomization axes is:

| Axis | Status | How |
|---|---|---|
| Subnet placement (public/private) | **covered, free** | `make reachability-lab-aws` - two instances behind the *same* open security group, only the routed one is flagged. Verified on a real account. |
| Permission boundary | **covered, free** | `make boundary-lab-aws` - this is the one that produced the engine's first genuine false positive; the engine now evaluates boundaries and the lab is its regression test. |
| Real privesc primitive | **covered, free** | `make redteam-aws` - the oracle answers both ways, so precision over escalation claims is an uncensored measurement. |
| Resource scoping (`*` / single) | **covered, free** | `perspectivegraph redteam -principal <arn> -resource <arn>` puts the question to AWS over one resource instead of `*`. Without it a resource-scoped grant answers `implicitDeny` and is indistinguishable from no grant, so `-compare` reports the engine's `resource_scoped` claim as *unsettled* rather than refuting a question nobody asked. |
| Condition keys | **half covered, free** | The oracle no longer mistakes them for refusals: an `implicitDeny` carrying `MissingContextValues` is reported as unsettled, names the keys, and is excluded from the calibration set. *Settling* one - passing `--context-entries` - is deliberately not built: whether an `aws:SourceIp` or MFA condition holds is a fact about the attacker, not a judgement the oracle should make for you. |
| SCP on the OU | **blocked on cost, not on code** | Requires AWS Organizations. Enabling it on a free-tier account forfeits the credits immediately, so this waits for an account where that does not matter. |
| IMDS posture (v1/v2) | **genuinely needs this lab** | Distinguishing p≈0.9 from p≈0.6 on the ASSUMES hop needs a real instance and a real SSRF. No API can settle "did the attacker get code execution". |

That last row is the whole remaining justification for building this. It is also the hop
that makes path *scores* uncalibratable by the oracle alone: every internet-origin path
contains it, so those paths can be refuted but never confirmed, and a calibration set
built from them is censored. See the guard in
[`internal/redteam`](../../backend/internal/redteam) (`CalibrationGrade`).

## What the lab would do

Stand up one labelled environment per apply, randomized on the axes above, whose ground
truth the engine cannot see. The engine scores the paths, the attempt is made for real,
and the outcome pairs a prediction with reality:

```
randomized lab  ─▶  ingest  ─▶  engine scores paths  ─▶  each path attempted
      ▲                                                          │
      └──────────  calibration flywheel  ◀── refuted/confirmed ──┘
                   (internal/validation)
```

`variables.tf.example` declares the knobs. A real build would add `main.tf` (the VPC,
EC2 and IAM they parameterize) and `outputs.tf` (the ground-truth manifest: which paths
*should* be exploitable given the randomized reality, plus the ingest bundle, so a run
is self-describing).

## Safety rails (non-negotiable, if it is ever built)

- **Dedicated, disposable account only.** This lab exists to stand up genuinely
  exploitable infrastructure. It must never run near anything real. Use an account with
  a hard budget alarm and nothing else in it.
- **Destroy immediately.** Labs are ephemeral; leaving one running is both cost and
  exposure. Note that unlike the free labs, this one runs compute and is **not** free.
- **Prefer the dry run.** Anything settleable with `iam:SimulatePrincipalPolicy` should
  be settled that way, as the existing labs do. Real exploitation is the last resort,
  reserved for the one axis that requires it.
- **Distribution shift is a known limitation.** A calibration fitted on synthetic labs
  may not transfer to a real estate. Read the *per-score-bucket* reliability (does "0.8"
  fire ~80% of the time?), not the marginal base rate, which is the least transferable
  part.

## Meanwhile

Every axis a dry run can reach is now covered by
[`internal/redteam`](../../backend/internal/redteam), and one of them found a real bug.
What is left needs something no API provides: an Organization for the SCP row, and real
exploitable compute for the IMDS row - the one axis that justifies building this lab at
all. Anything a future axis *can* settle with a simulation should still be settled that
way first, the way `make boundary-lab-aws` does it: engine and AWS side by side, non-zero
exit on disagreement.
