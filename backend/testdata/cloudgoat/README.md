# CloudGoat attack-path benchmark

A ground-truth battery for the attack-path engine. Each scenario models a known
[Rhino CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) vulnerable lab
as real AWS `describe-*` fixtures plus a `scenario.json` that declares the attack
paths the engine **must** find. The runner
([`internal/benchmark`](../../internal/benchmark/cloudgoat.go)) drives the same
pipeline the live stack does - fixtures → `aws` connector → normalization →
in-memory graph → analyzer - and grades the result as precision / recall. No AWS
account, no network.

```
make bench-cloudgoat        # prints the per-scenario precision/recall table
```

It also runs under `make test` (plain `go test ./...`), so it is **CI-gated**:

| signal | meaning |
|---|---|
| `recall < 1.0` | the engine stopped finding a known attack path (**false negative**) |
| `precision < 1.0` (exhaustive scenarios) | the engine invented a path that isn't real (**false positive**) |

## Why it exists

The engine's threat-model scope (internet-origin by default, credential-origin
opt-in) only became visible when it was validated against a real vulnerable lab.
This benchmark turns that one-off validation into a permanent regression.

## What this benchmark is NOT

It grades **detection correctness** (does the engine surface the right paths?), not
**probability quality** (are the engine's scores well-calibrated?). Those are
orthogonal axes, and this data must **not** be fed into the calibration flywheel
(`internal/validation`): CloudGoat labs are exploitable *by construction*, so every
declared path is a true positive and the sample's base rate is 1.0 by design rather
than by nature. Pairing those all-positive outcomes with their predicted scores
would yield a flattering Brier and a "scale every score up" recommendation drawn
from a biased sample - false empirical grounding, which is worse than none. Note too
that the negative control cannot offset it: a correctly-withheld path carries no
predicted score, so it contributes nothing to calibration.

Legitimate calibration data needs genuine **refuted** verdicts - paths the engine
surfaced that then failed when actually attacked - at the environment's real base
rate. That comes from running exploitation against a lab (or real BAS/red-team
runs), not from authoring fixtures. See the calibration section of the root README.

## Scenarios shipped

| directory | lens | asserts |
|---|---|---|
| `ec2_ssrf` | internet-origin | SSRF → IMDS → instance role → admin (`iam:PassRole`+`lambda:CreateFunction`) |
| `iam_privesc_by_attachment` | credential-origin | leaked user (`iam:AttachUserPolicy`) → admin; **and** zero paths with the lens off (the M1 finding) |
| `ec2_private_subnet_no_path` | internet-origin | reachability precision: an SG open to `0.0.0.0/0` in a **private** subnet is not exposed → **no** path |
| `iam_privesc_denied_by_guardrail` | credential-origin | policy-evaluation precision: an account-wide explicit **Deny** beats the Allow, so the privesc edge and the path are withheld → **no** path |

## Scenario format

A scenario directory contains:

- `cloudnet-sample.json` - the network feed: `describe-security-groups` +
  `describe-instances` + (optional) `subnets` / `route_tables` / `network_acls` /
  `instance_profiles` / `vpc_peerings`. Optional; omit for identity-only scenarios.
- `iam-sample.json` - the identity feed: `iam get-account-authorization-details`
  shape (`UserDetailList` / `RoleDetailList` / `GroupDetailList` / `Policies`).
  Optional; omit for network-only scenarios.
- `scenario.json` - metadata + ground truth:

```json
{
  "name": "ec2_ssrf",
  "rhino_scenario": "ec2_ssrf",
  "description": "One line on what the path is.",
  "seed_iam_users": false,
  "credential_origin": false,
  "exhaustive": true,
  "expected_paths": [
    {
      "id": "imds-to-admin",
      "source_name": "cg-ec2-ssrf-app",
      "target_name": "account-admin (effective)",
      "must_traverse_names": ["cg-ec2-ssrf-role"],
      "must_traverse_labels": ["VirtualMachine", "IAM_Role"],
      "min_score": 0.5
    }
  ]
}
```

- `seed_iam_users` - the threat-model lens: `false` = internet-origin only
  (default), `true` = also seed from IAM users (the `SEED_IAM_USERS` lens).
- `credential_origin` - when `true`, the runner additionally asserts the scenario
  yields **zero** paths with the lens off (pins the credential-origin contract).
- `exhaustive` - when `true`, precision must be `1.0`: every crown-jewel path the
  engine finds must be a declared one. Use `expected_paths: []` for a pure negative
  control.
- An `expected_paths` entry matches a found path when its `source_name` /
  `target_name` agree, it traverses every `must_traverse_names` / `_labels`, and
  its score clears `min_score`. Empty fields are unconstrained.

## Graduating a scenario to real ground truth

The shipped fixtures are **hand-authored** to model each scenario's published
attack path faithfully - enough to guard against regressions. To validate against
genuine ground truth, replace a scenario's fixtures with captures from a live lab:

```bash
cloudgoat create ec2_ssrf                     # spin up the real vulnerable lab

# network feed
aws ec2 describe-security-groups  > sg.json
aws ec2 describe-instances        > inst.json
aws ec2 describe-subnets          > subnets.json
aws ec2 describe-route-tables     > rt.json
aws ec2 describe-network-acls     > nacl.json
aws iam list-instance-profiles    > profiles.json
# → assemble into cloudnet-sample.json (keys: security_groups, instances,
#   subnets, route_tables, network_acls, instance_profiles)

# identity feed
aws iam get-account-authorization-details > iam-sample.json

cloudgoat destroy ec2_ssrf                     # tear it down (keep costs at ~zero)
```

Then write `scenario.json`'s `expected_paths` from the lab's known escalation, and
run `make bench-cloudgoat`. The runner is unchanged - only the fixtures get more
real. Do **not** commit live account IDs or ARNs you consider sensitive; the demo
account id `111111111111` is used throughout the shipped fixtures.
