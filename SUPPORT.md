# Support

What is supported, for how long, and what to do if your organisation cannot simply "run
the latest".

This document exists because "supported versions: the latest release" is a *policy*, and a
policy a change-advisory board reads has to say more than a maintainer assumes. Everything
below is written so it can be checked or refused rather than taken on trust.

## The policy

**Fixes land on the newest release. Nothing is backported.**

| Version | Receives fixes |
|---|---|
| the newest tagged release, and `main` | yes |
| every earlier tag | no - upgrade to the newest |

There is no long-term-support branch, and 1.0 did not create one: it froze the *interface*,
not a maintenance window - see [API stability](docs/API-STABILITY.md).

### Why, said plainly

One maintainer, and a cadence measured in days rather than quarters: **six minor releases
in the eight days after 1.0**. Backporting security fixes onto a maintenance branch is a
promise about future weeks of one person's time, and this project would break it. A support
window that exists on paper and fails on the day a CVE lands is worse than an honest
"upgrade", because the paper one gets written into somebody's risk register as a control.

So the commitment is made where it can be kept: on **how fast a fix appears**, and on **how
cheap the upgrade is**.

## What you get instead of backports

### 1. Security fixes on a clock

Measured from the moment a report is confirmed, to a public release carrying the fix:

| Severity (CVSS) | Target |
|---|---|
| Critical | **7 days** |
| High | **30 days** |
| Medium / Low | the next release that suits it |

Acknowledgement within 3 business days and triage within 7 are in
[SECURITY.md](SECURITY.md), along with how to report privately. These are targets a single
maintainer can hold, not an SLA you can buy - if one slips, the advisory says so rather
than the date quietly moving.

### 2. An upgrade that is specified rather than hoped for

The reason "always run the latest" is a workable policy here is that upgrading is designed
to be boring:

- **SemVer, with the stable surface enumerated.** The GraphQL API, the ingest contract, the
  operational endpoints, the environment variables and the CLI only break in a major
  release. [API stability](docs/API-STABILITY.md) lists them and the deprecation path.
- **The schema contract is machine-guarded.** `docs/api/schema.graphql` is a snapshot and a
  test fails CI on any drift, so a breaking API change cannot arrive unnoticed in a patch.
- **A CHANGELOG per release**, generated from Conventional Commits rather than written from
  memory.
- **No migration step.** The backend creates and upgrades its own graph and governance
  schema on start-up. There is nothing to run between versions.
- **Rollback is a redeploy** of the previous digest. One caveat worth knowing before you
  need it: a release rolled back onto a governance database that a *newer* release already
  migrated refuses to start rather than writing a schema it does not understand - it fails
  loudly instead of corrupting state, so take the backup in
  [OPERATIONS §4](docs/OPERATIONS.md#4-backup--restore-the-graph-is-sensitive-data) first.
- **The graph is derived state.** In the worst case it is rebuilt by re-ingesting the
  feeds, so an upgrade gone wrong costs you history, not the map.

### 3. Artefacts you can pin and verify

Every release publishes digest-addressable images and signed binaries with an SPDX SBOM and
SLSA build provenance. Pin the digest, verify the signature before rollout, and your
"approved version" is a thing with a hash rather than a moving tag - see
[SECURITY.md](SECURITY.md#our-own-supply-chain) for the verification commands.

## Running this where change control applies

The practical recipe, in the order a release manager would want it:

1. **Pin by digest**, not by `latest` and not by a floating major tag.
2. **Watch releases** - on GitHub, *Watch → Custom → Releases* - so a new version is a
   notification rather than a discovery. Security releases are also published as GitHub
   advisories.
3. **Verify** the cosign signature, the SBOM and the provenance attestation as a gate in
   your own pipeline, so an unverifiable artefact fails your process rather than mine.
4. **Read the CHANGELOG entry** for the target version; it names any deprecation.
5. **Stage it**, then roll forward with the backup already taken.
6. **Keep your configuration under your own change control.** The environment variables are
   part of the stable surface, so your `.env` or Helm values are a reviewable artefact that
   survives upgrades.

If your process requires a fixed version for a period, pin the digest and treat each new
release as a change to assess - but be explicit internally that an unpatched pin carries
the risk, because no fix will be issued for it here.

## What "support" does not mean here

- **There is no commercial support, no SLA and no paid tier.** Nobody is on call.
- **Issues and pull requests are best-effort**, answered when the maintainer has time. The
  only stated response times in this project are for security reports.
- **Security reports do not go in public issues** - use private reporting, see
  [SECURITY.md](SECURITY.md).
- Questions about *using* it belong in an issue; the [manual](docs/MANUAL.md) is the
  reference and is meant to answer most of them first.

## Continuity

One maintainer is a real risk and pretending otherwise would be the same mistake as an
unkeepable support window. What reduces it is that nothing about this project requires the
maintainer to keep existing:

- **Apache-2.0**, so a fork needs no permission.
- **No telemetry, no phone-home, no hosted component.** Nothing you run depends on
  infrastructure anyone else operates.
- **The entire build and release path is in the repository** - the workflows, the signing,
  the SBOM and provenance generation. A fork inherits a working pipeline: the release
  workflow derives its signing identity from whichever repository runs it, so a fork signs
  its own images without editing anything. What a fork does have to change is the published
  image namespace, which is written out in `README.md`, `SECURITY.md`, `docs/MANUAL.md` and
  the chart's `values.yaml`, along with the verification commands that name it.

That is not a substitute for a second maintainer. It is what makes taking over possible
rather than theoretical, and it is [worth contributing to](CONTRIBUTING.md).
