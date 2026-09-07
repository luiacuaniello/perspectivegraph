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

## 1.12.7

### The chart could not install at all, and now can

**Affects you if** you ever tried `helm install` with the default values. It failed, and
this release is the fix.

The bundled database and broker pods declared `runAsNonRoot: true` without a `runAsUser`,
and every image the chart deployed leaves `USER` unset - which is root. The kubelet refuses
that combination outright:

```
container has runAsNonRoot and image will run as root
```

Both pods sat in `CreateContainerConfigError` and the backend waited behind them in
`Init:0/2` forever. CI never saw it because it rendered the templates and checked them
against the restricted Pod Security Standard - which they passed - and never installed
them. `make chart-install` now stands up a kind cluster and installs the chart with default
values on two Kubernetes versions, so this class of failure cannot return silently.

**Action: none, if you were using the bundled database** - it could not have been running,
so there is nothing to migrate. An install pointed at your own PostgreSQL+AGE was never
affected.

### `postgres.image` is now a map, not a string

**Affects you if** you override the bundled database image, typically as
`--set postgres.image=...` in a pipeline. It now follows the same shape as the backend and
dashboard images:

```yaml
postgres:
  image:
    repository: ghcr.io/luiacuaniello/perspectivegraph-postgres
    tag: "" # empty = the chart's appVersion
```

A string value now fails to render rather than being ignored, which is the safe direction.

### The bundled demo database is built here instead of pulled

The image moves from `apache/age:release_PG17_1.7.0` to
`ghcr.io/luiacuaniello/perspectivegraph-postgres`, built from `deploy/postgres/Dockerfile`:
the same PostgreSQL 17 and Apache AGE 1.7.0, on Alpine instead of Debian, signed with
cosign and carrying an SBOM and provenance like the other two.

**Action: none.** The postgres uid is deliberately kept at 999, the Debian value, so an
existing `docker compose` volume is read by the new image unchanged - this was tested by
writing a graph with the old image and reading it back with the new one. On Kubernetes
`PGDATA` moves to a subdirectory of the mount, which no running cluster can notice for the
reason in the first note.

Why bother, for a demo: `apache/age` is not stale - it is the official `postgres:17-trixie`
image plus the extension - but its Debian base carried fourteen criticals, **thirteen of
them perl and libxml2 with no fix published in any version**, so no rebuild by anyone would
have cleared them. Alpine ships no perl. The chart's report goes from 430 findings to 4.

### NATS moves to the scratch image

Same server, same version, no Linux userland around it - which was twenty of that image's
twenty-three findings. **Action: none** unless you run the compose stack with a custom
health check for NATS: there is no shell in the image to run one, and `docker-compose.yml`
now waits for the broker with a busybox container instead.

---

## 1.12.5

### The chart refuses to publish an unauthenticated instance

`service.type` is now a value, defaulting to `ClusterIP`, and `LoadBalancer` or `NodePort`
is guarded exactly like the ingress: the chart refuses to render either without a
credential. It is offered on purpose - without it, exposing the backend meant patching the
Service by hand, which no guard in the chart could see. Nothing changes for an install
that leaves it at `ClusterIP`.

The dashboard also carries a banner, not dismissible, whenever `/auth/config` reports that
no credential is required. It is what covers the exposure a chart cannot see - a patched
Service, a hand-written Ingress - and it appears in `make demo` too, which runs open by
design.


**Affects you if** you install the Helm chart with `ingress.enabled: true` and have not
configured a credential. `helm upgrade` will refuse to render rather than apply.

Enabling the ingress is the moment an install becomes reachable, and this chart's ingress
routes both `/graphql` — this environment's map of how to breach it — and `/ingest`, the
write side that decides what the engine reasons over. The backend has always refused to
start unauthenticated under `PG_ENV=production`, but that gate only fires for an operator
who declared production; an install left on the demo default was reachable and open, with
nothing but a startup warning that scrolls past in a log.

The chart now fails to render in that combination. Set one of:

```yaml
auth:
  apiTokens: "s3cr3t:admin"        # or oidc.jwksUrl with issuer and audience
ingest:
  hmacSecret: "another-secret"     # or hmacSecrets for per-tenant keys
```

Credentials supplied through `secrets.existingSecret` satisfy the guard: the chart cannot
read a secret's contents, so an operator using one is trusted rather than blocked.

If an open instance is the point — a public read-only demo — say so explicitly:

```yaml
ingress:
  allowUnauthenticated: true
```

Nothing changes for an install with `ingress.enabled: false`, which is the default, or for
`make demo` and Docker Compose, which bind to 127.0.0.1 only.

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
