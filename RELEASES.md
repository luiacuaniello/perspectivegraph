# Releases

How a release of PerspectiveGraph is made, what it publishes, and what to do when one goes
wrong.

The rules a release follows are written elsewhere, and this file does not repeat them: which
versions receive fixes is in [SUPPORT.md](SUPPORT.md), what a version number promises in
[API stability](docs/API-STABILITY.md), why there is no fixed cadence in
[GOVERNANCE.md](GOVERNANCE.md#releases), and how a fixed vulnerability is disclosed in
[SECURITY.md](SECURITY.md#how-a-fix-is-disclosed). This is the procedure that carries them
out.

## From commits to a version

[release-please](https://github.com/googleapis/release-please) reads the
[Conventional Commits](https://www.conventionalcommits.org) merged into `main` since the last
release, and their subjects decide the version:

| Merged since the last release | Release |
|---|---|
| a breaking change: `feat!:`, or a `BREAKING CHANGE:` footer | major |
| a `feat:` | minor |
| a `fix:` | patch |
| only `chore:`, `docs:`, `test:`, `ci:`, `refactor:`, `build:` or `style:` | none - they ship with the next release, and the CHANGELOG leaves them out |

Dependabot titles its updates `chore(deps)` and `chore(ci)`, so an update never cuts a
release by itself. When one fixes something in what a release ships - a Go toolchain with a
standard-library fix, say - merge it as a `fix:` that names what it fixes, as 1.38.3 did for
Go 1.27.3.

Two footers ask for more than a version. `BREAKING CHANGE:` is the Conventional Commits one;
`BEHAVIOUR CHANGE:` is this project's, for a change that alters what a deployment does
without breaking the stable interface - a control that starts refusing something, a default
that flips. Either way an operator has to be told what to do, and that is the job of
[docs/UPGRADING.md](docs/UPGRADING.md), not of the CHANGELOG: a pull request whose commits
carry either footer fails the *Behaviour changes carry a note* check until it adds a section
there.

What release-please reads is the commit that lands on `main`. A squashed pull request of one
commit keeps that commit's subject; one of several takes the pull request's title, which the
*Conventional PR title* check holds to the format. It reads the **last paragraph** of the
message too, and takes one that starts with a type for one more change: a documentation
commit that ended in a `fix(site): …` paragraph cut 1.27.1 on its own, with a CHANGELOG line
that stops mid-sentence. Say a second change in prose - "Also fixes …" - and never as the
last paragraph.

## How a release is cut

1. **release-please keeps a release pull request open.** On every push to `main`,
   [its workflow](.github/workflows/release-please.yml) updates one pull request,
   `chore(main): release X.Y.Z`. It moves the version in `.release-please-manifest.json`,
   adds the release's section to the [CHANGELOG](CHANGELOG.md), and rewrites every version
   string that carries release-please's marker - the comment that ends the `version:` line
   of [the chart](deploy/helm/perspectivegraph/Chart.yaml) - in the files
   [`release-please-config.json`](release-please-config.json) lists: the chart, the compose
   files, the Trivy plugin manifest, and the commands in the README, SECURITY.md, the
   operations runbook and the manual. A new file that names the version needs both, the
   marker on the line and an entry in `extra-files`. A test fails on a file that carries the
   marker without the entry, but nothing finds a version written without the marker: that
   one keeps naming the version it was written with.
2. **Merging it is the release.** release-please tags the merge commit `vX.Y.Z` and creates
   the GitHub release with the CHANGELOG section as its notes, and the same workflow then
   calls [Publish images](.github/workflows/publish-images.yml) with the tag. The release
   pull request goes through the same required checks as any other.
3. **Publish images builds from the tag**, not from `main`, and publishes what the next
   section lists. Its chart job refuses to publish when `Chart.yaml` names a version other
   than the tag.

Merging into `main` takes a pull request that passes the required checks, with signed
commits and a linear history, and the ruleset that enforces this lets nobody bypass it, the
maintainer included. So whoever can merge the release pull request cuts the release: today,
the [maintainer](MAINTAINERS.md).

## What a release publishes

| What | Where | Verified by |
|---|---|---|
| The images: `perspectivegraph` (the engine, which is also the MCP server), `perspectivegraph-dashboard` and `perspectivegraph-postgres`, each for `linux/amd64` and `linux/arm64` | `ghcr.io/luiacuaniello/`, tagged `vX.Y.Z` | a cosign keyless signature, an SPDX SBOM attested to the image and attached to the release, and SLSA build provenance |
| The binaries: Linux and macOS on amd64 and arm64, Windows on amd64 | the GitHub release | `SHA256SUMS`, signed in `SHA256SUMS.sigstore.json` (the GitHub Action reads the same file as `SHA256SUMS.bundle`), and `perspectivegraph.intoto.jsonl`, the build provenance of every archive |
| The Helm chart | `oci://ghcr.io/luiacuaniello/charts/perspectivegraph`, and the `.tgz` on the GitHub release | a cosign keyless signature |

The commands that verify them are in [SECURITY.md](SECURITY.md#our-own-supply-chain) for the
images and the binaries, and in [Deploy to Kubernetes](docs/manual/kubernetes.md) for the
chart.

Around those:

- `latest` moves only when the tag being built is the newest release, so publishing an
  older tag again never drags it backwards.
- The archives carry no version in their names, so `releases/latest/download/<name>` is a
  URL that does not go stale.
- The floating tag `v1`, which `uses: luiacuaniello/perspectivegraph@v1` resolves, moves to
  the release only once its images and binaries exist: the action downloads one of those
  binaries. It follows stable `vX.Y.Z` tags only, and so does the
  [MCP Registry](https://registry.modelcontextprotocol.io) entry
  `io.github.luiacuaniello/perspectivegraph`, which the same run updates.
- Artifact Hub reads the chart from the registry, and the Trivy plugin manifest on `main`
  points at the new archives once the release pull request merges. Neither needs a step of
  its own.
- The [documentation site](https://docs.a3thinker.it) is not part of a release: it is
  published from `main` on every merge that touches the docs. Between a merge and the
  release that carries it, it can describe something the newest release does not do yet.

## Before merging the release pull request

- **The upgrade notes name this version.** A section in UPGRADING.md is written before
  anyone knows which release it lands in, so if a `feat:` merged after it turned the
  expected patch into a minor, its heading names the wrong version. Correct it in a pull
  request first.
- **The chart's security annotations match the release.** A release that fixes a
  vulnerability carries, in `deploy/helm/perspectivegraph/Chart.yaml`, the two annotations
  that make Artifact Hub mark the version as a security update:

  ```yaml
  annotations:
    artifacthub.io/containsSecurityUpdates: "true"
    artifacthub.io/changes: |
      - kind: security
        description: <what the fix does, in one line>
        links:
          - name: GHSA-xxxx-xxxx-xxxx
            url: https://github.com/luiacuaniello/perspectivegraph/security/advisories/GHSA-xxxx-xxxx-xxxx
  ```

  A release that fixes none carries neither. Add or remove them in an ordinary pull request,
  not in a commit on the release branch, which release-please rewrites on every push to
  `main`. A chart version is pushed once and never replaced, so a security release that
  ships without them stays unmarked, as 1.39.2 did.
- **The advisory names this version as the patched one.** It is still a private draft until
  the release exists. Request its CVE while the fix is in review: GitHub reviews each
  request by hand.

## After the release

1. **Every job of the run is green**: the three image legs, the binaries, the chart, the
   floating tag and the MCP Registry. A failed one is handled as in the next section, not by
   re-running it straight away.
2. **Verify from your own machine**, with the commands a user is given. The workflow checks
   the signatures of the binaries and the chart on the runner that made them, and those of
   the images not at all; this checks every one of them on the path a user takes, from the
   registry and the release page.
3. **After a security release, publish the advisory**, then add its link to the release
   notes, next to the fix: the notes are generated from commit subjects, so the link goes in
   by hand, on the release page. In the next pull request, take the chart's security
   annotations out again.

## When a release fails halfway

It has happened twice, both times a tool download from GitHub's release CDN failing after
something was already published: the chart on 1.13.0, the dashboard image on 1.15.0. What
makes it delicate is that not every job can safely run twice. So first establish what was
published - the tags in GHCR, the assets on the release, where `v1` points - and then finish
only what is missing.

| Job | Run it again? |
|---|---|
| `publish`, one leg per image | Only for a leg that pushed nothing, or whose image is incomplete: no signature, SBOM or provenance. A build is not reproducible, so a second one is a new digest under the same tag. |
| `binaries` | Yes, if nothing is on the release yet. Otherwise it replaces the archives, and the checksums and their signature with them, under files people may already have downloaded. |
| `chart` | Yes. It asks GHCR first, and a version already there is reused, never pushed again. |
| `major-tag` | Yes. It points `v1` at the same tag. |
| `mcp-registry` | Yes. It asks the registry first, and skips a version it already has. |

*Re-run failed jobs* does not always pick up the jobs that depend on the failed one: read the
list in GitHub's confirmation dialog before you confirm. Running *Publish images* by hand on
an existing tag rebuilds every image, so it is not a lighter retry. And when the build
itself is broken, cut a patch release rather than change what an existing tag builds: a
version has to mean one thing.
