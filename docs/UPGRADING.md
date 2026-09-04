# Upgrade notes

What changes for a **running deployment** when you move between versions - the settings you
have to set, the requests that start failing, the behaviour that is no longer what it was.

This file exists because the [CHANGELOG](../CHANGELOG.md) does not carry it. That file is
generated from Conventional Commit *subjects*, so it names what changed in one line and
drops the paragraph underneath explaining what an operator has to do about it. A one-line
entry is fine for a bug fix and useless for a release that refuses writes until a new
variable is set.

**Only versions that need an action appear here.** A version missing from this list is one
you can upgrade into without touching your configuration - which is most of them. Follow
the upgrade recipe in
[SUPPORT.md](../SUPPORT.md#running-this-where-change-control-applies) either way: pin by
digest, take the backup, stage it.

---

## 1.12.4

### The bundled demo database moves to PostgreSQL 17

**Affects you if** you run the bundled database - `make demo`, `docker compose`, or a Helm
install left on `postgres.enabled: true`. An install pointed at your own PostgreSQL+AGE is
unaffected, and that is what production should be doing anyway.

The image moves from `apache/age:release_PG16_1.6.0` to `release_PG17_1.7.0`. **A
PostgreSQL major version cannot read the previous major's data directory**, so an existing
demo volume will not start under it. The data is derived - the graph is rebuilt by
re-ingesting - so the fix is to drop the volume:

```bash
make down            # `docker compose down -v` removes the volumes
make demo
```

On Kubernetes, delete the PVC before upgrading if you were using the bundled database.

Why bother, for a demo: the older image carried 19 critical and 191 high advisories, and
it is what Artifact Hub scans and reports on the chart's page. The newer one is 14 and 97.
Nothing there is in code this project ships - both first-party images scan clean - but a
default install deploying it is a default install answering for it. Thirteen of the
remaining critical findings have no fix available from Debian in any version.

The NATS image moves with it, from 2.12.11 to 2.14.6. That one was entirely ours to fix:
all thirteen of its findings had upstream fixes, and the new image is clean of criticals.
No action is needed - NATS reads no persistent state in this deployment.

## 1.12.1

### The chart installs the app version it was built with, not `latest`

**Affects you if** you install the Helm chart without setting `backend.image.tag` or
`frontend.image.tag` - which is the default.

Both defaulted to `latest`. A chart is a versioned, signed artefact that was tested
against one build of the application, and `latest` floats: chart 1.12.0 would deploy
whatever image had been pushed most recently, which is not necessarily the one it
declares. The default is now empty, and an empty tag resolves to the chart's own
`appVersion`.

Concretely, `helm install` with defaults moves from `…/perspectivegraph:latest` to
`…/perspectivegraph:v1.12.1`. If you were relying on `latest` to pick up new images
without touching your values, set it back explicitly:

```yaml
backend:
  image:
    tag: latest
```

Better, pin a digest - `tag: "@sha256:…"` - which is what
[OPERATIONS](OPERATIONS.md) asks for in production and what the release publishes.

There was a second, quieter consequence. Artifact Hub scans the images a chart deploys
and publishes the report on the chart's page; with a floating tag it was scanning
something other than the release.

## 1.11.2

A security release. Three behaviours changed, each of them a control that now refuses
something it used to allow. All three are silent in the sense that nothing crashes - so if
one applies to you and you do not act, the effect is a feature quietly not working.

### Forge writes need `REPO_ALLOWLIST`

**Affects you if** `GITHUB_TOKEN` or `GITLAB_TOKEN` is set and you are not in dry-run.

PR comments, the merge-gate commit status and remediation PRs now write **only** to
repositories you name. The destination was previously read from an ingested node property
(`repo_slug`), which means it was chosen by whoever can post an event - and the ingest
endpoint is reachable by every scanner holding the shared HMAC key. A `success` commit
status in a repository where this check is *required* opens a merge gate, so this was worth
closing at the cost of a required setting.

Set it to the repositories that are yours, as exact slugs or an owner wildcard:

```bash
REPO_ALLOWLIST=acme/payments-api,acme/*
```

With it empty, every real write is refused. You will see this once at start-up:

```
forge token set but REPO_ALLOWLIST is empty: every PR comment, commit status and
remediation PR will be refused
```

and one line per refusal, naming the repository it declined (`pr comment refused:
repository not allowed`). `POST /remediation/pr` answers `422` naming the setting. Dry-run
is exempt - it makes no outbound call - so a demo keeps printing what it would post.

### `POST /ingest/events` rejects labels outside the ontology

**Affects you if** you hand-author events with a label or edge type that is not in the
documented vocabulary, **and** you run the in-memory graph backend.

The vocabulary was already enforced by the Apache AGE store, so an AGE deployment saw no
change; the in-memory backend accepted any string, and those values reached code that
assumes a closed set - including the prompt the AI layer builds. The check moved to the
ingest door and to the single writer into the graph.

A rejected request answers `400` and names the value:

```
outside the ontology: node "n": unknown label "MyCustomThing"
```

Map your events onto the labels and edge types listed in
[MANUAL §5](MANUAL.md). If you need a value that is not there, open an issue - adding one
is a minor release, and a local string that only worked on one backend was never portable.

### An `apps`-scoped principal can no longer act outside its applications

**Affects you if** any token or OIDC claim carries an `apps` allowlist. A principal without
one is unaffected, and that is most deployments.

Suppressions, tickets and validations are keyed by attack-path id and were filtered by
tenant alone, while the path reads behind them were already filtered by application. So a
principal scoped to one application could suppress a path belonging to another - hiding a
real finding from the team that owns it. Those boards are now filtered, and a write against
a path outside the caller's applications answers `404 attack path not found (or out of your
scope)`.

If a scoped principal of yours legitimately needs a wider view, widen its `apps` claim; if
it needs the whole tenant, drop the claim.

One thing deliberately did **not** change: the tenant-wide calibration and
precision/recall aggregates are still tenant-wide. They measure the engine rather than any
application, name no path or asset, and GraphQL serves the same numbers - so scoping only
the REST board would have been a control in name only. It is written up in the
[threat model](THREAT-MODEL.md).
