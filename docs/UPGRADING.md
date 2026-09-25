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

## 1.20.0

### Ingest requests can be signed v2, and v1 can be turned off

**Affects you if** anything signs ingest requests itself - a script built on the MANUAL
recipe, a webhook, a CI step other than the gate.

The v1 signature (`X-PerspectiveGraph-Signature: sha256=…`) covers the body alone. The
repository and commit a report counts against travel in the query, so a captured request
could be replayed at any time, or its `?sha=` changed to put its findings - or its lack of
findings - on another commit. v2 (`X-PerspectiveGraph-Signature-V2` with
`X-PerspectiveGraph-Timestamp`) covers the time, method, path, parameters and body, and
each signature is accepted once within five minutes. The `gate` subcommand, the GitHub
Action and the Postman collection now send both.

**Action: none to keep working** - v1 stays accepted (`INGEST_HMAC_ACCEPT_V1=true`). To
close the hole: move your senders to v2 (MANUAL, "Authentication"), watch
`perspectivegraph_ingest_signatures_total{version="v1"}` stay at 0, then set
`INGEST_HMAC_ACCEPT_V1=false` (Helm: `ingest.hmacAcceptV1: false`). A proxy in front of
ingest must pass the path through unchanged: the path is signed.

### Large events are split, and the gate waits for the whole report

**Affects you if** you ingest large cluster or account dumps, or run the merge gate.

An event over one bus message (1 MiB on a default NATS) used to be refused at ingest with
a 502, so a large estate never reached the graph. It is now split into chunks. The ingest
response carries a `batch` id, and GraphQL `ingestBatch(id)` says when every chunk has
been applied; the gate waits for that and takes its verdict from a pass after it, because
a pass between two chunks would have seen part of the report.

**Action: none.** A gate older than 1.20 still works against this engine, as before -
without the wait.

### An edge waiting for its endpoint is parked, not redelivered

**Affects you if** your feeds send edges to assets another feed describes.

Such an edge used to send its whole event back for redelivery, eight times in about four
minutes, and then to the dead-letter stream. It is now parked and lands in the write
that brings its endpoint, from any feed or replica, for up to seven days.

**Action: none.** Expect fewer dead-lettered events. `perspectivegraph_graph_pending_edges`
counts what is parked, and the shipped `PerspectiveGraphPendingEdgesGrowing` alert fires
when it keeps rising - a feed naming assets nothing else describes.

### Reading a tenant no longer creates it; tenants share one connection pool

**Affects you if** you run several tenants, or sign users in with OIDC tenant claims.

A read under a tenant nobody had written used to create its graph, a pool of eight
database connections and an analyzer loop - so the number of tenants, not the operator,
set how many connections a replica needed. A never-written tenant now reads as an empty
graph, and all tenants' graphs share one pool of eight connections per replica.

**Action: none.** Size `max_connections` for eight graph connections per replica,
whatever the tenant count (plus the governance pool and the leader's connection).

### The auth-denial alert watches a new counter

**Affects you if** you loaded `deploy/observability/prometheus-alerts.yaml`.

`PerspectiveGraphAuthDenialSpike` matched `code=~"401|403"` on a counter that records only
status classes (`4xx`), so it could never fire. It now reads
`perspectivegraph_auth_denied_total`, which counts refused credentials on the API and on
ingest by reason.

**Action:** reload the alert rules.

### Smaller changes, no action

- `perspectivegraph healthz` - the container healthcheck - speaks HTTPS when the API
  serves TLS itself; it used to mark such a backend unhealthy. It verifies the listener
  against the process's own `TLS_CERT_FILE` and a name that certificate lists, so the
  certificate must carry a DNS name or IP address (any certificate a browser accepts does).
- The file-backed governance stores force their writes to disk. On macOS, where a sync is
  slow, importing many verdicts into the file store takes a few seconds longer.
- OIDC tokens signed ES256/ES384/ES512 are accepted, each only with a key of its curve.
- A node listed twice in a graph - duplicate vertices written by concurrent replicas
  before 1.19 - counts once in the risk simulation. It used to count twice: a compromise
  probability of 2 and an interval of NaN.
- A node written without a name no longer fails reading the whole graph on Apache AGE.

---

## 1.19.0

### The event stream keeps what is still to be processed, and nothing else

**Affects you if** you upgrade a deployment whose NATS already holds the `PERSPECTIVE`
stream - which is every upgrade.

The stream used to keep every event ever ingested: limits retention with no limit set, on
a volume nothing emptied. It now uses interest retention, so an event leaves as soon as the
backend acknowledges it, and `NATS_MAX_AGE` (default `168h`) drops one nobody drains. The
dead-letter stream keeps its events for the same `NATS_MAX_AGE`. The backend updates both
streams in place on its first start, and NATS then deletes every event already processed,
so the disk that history held is freed at once; events still waiting are kept and handled
as before, and nothing is replayed. Settings you made on the stream yourself - replicas,
above all, on a clustered NATS - are now kept: the backend used to reset them at every
start.

**Action: none, with two exceptions.**

- **A NATS older than 2.10** refuses to change a stream's retention, and the backend stops
  at startup with `stream configuration update can not change retention policy`. Upgrade
  NATS (the chart and Compose ship 2.15), or delete the stream and let the backend
  recreate it.
- **A consumer of your own on the stream** now holds events back: under interest
  retention an event stays until *every* consumer has acknowledged it. Remove consumers
  you no longer read from.

### A listener that cannot start now stops the process

**Affects you if** your logs from the previous version contain `http server failed`.

That line meant the listener named in it - `api`, `ingestion` or `metrics` - never served,
while the process stayed up without it. A taken port or an unreadable certificate now exits
with status 1 and the reason on the last line, and so does a bus connection that closes
for good or a consumer that stops.

**Action:** fix whatever the old log line named before upgrading, or the new version
crash-loops on it - which is the point: the old one was silently missing a port.

### Replicas no longer write the same asset twice

**Affects you if** you ran more than one backend replica against Apache AGE -
`values-ha.yaml`, or `backend.replicas` above 1.

AGE has no unique constraint, and replicas write concurrently, so two events naming the same
asset at the same moment could each create a vertex for it. Writes to a graph now take a
lock and converge on one vertex, but duplicates created before the upgrade stay: an update
reaches all of them, so they never go stale and the TTL pruner never removes them.

**Action:** check each tenant's graph (`perspective` is the default tenant's; others are
`perspective_<tenant>`):

```sql
LOAD 'age'; SET search_path = ag_catalog, "$user", public;
SELECT * FROM cypher('perspective', $$
  MATCH (n) WITH n.id AS id, count(*) AS copies WHERE copies > 1 RETURN id, copies
$$) AS (id agtype, copies agtype);
```

No rows: nothing to do. Rows: the graph is derived from the feeds, so the clean fix is to
rebuild it - take the backup (OPERATIONS §4), drop the graph
(`SELECT drop_graph('perspective', true);`), restart the backend, and let the scanners and
connectors re-ingest. Suppressions, tickets and the audit log are not in the graph and are
not affected.

### An edge waiting for its endpoint no longer holds back the rest of its event

**Affects you if** your feeds send edges to assets another feed describes.

The graph refused such an edge until its endpoint arrived, and stopped the event there: the
edges listed after it waited too, and after eight redeliveries (about four minutes) went to
the dead-letter stream along with it. Now every node and every other edge is written, and
only the waiting edges are retried. **Action: none.** Expect fewer dead-lettered events and
routes that used to appear late, or not at all, to appear on the first pass.

### A request may run at most twenty heavy analyses

**Affects you if** a script asks for many what-ifs in one request - typically
`verification` across a whole `remediationPlan`, or
`attackPaths { remediations { verification } }`.

Each fix's verification, each `whatIf`, each `riskSimulation` with its own `iterations` or
`seed`, and each `kShortestPaths` search is a full computation over the graph, and the
query guard, which prices a document before it runs, cannot see how long a list will be. On
a 4,344-node estate, verification across a 75-fix plan did not finish in five minutes. A
request now runs the first twenty of them - identical ones count once - and the rest of
its heavy fields answer with an error saying so. At most half the cores run them at once;
a request that waits 20 s for one is told the server is busy.

**Action:** ask for one fix's proof at a time with the new argument,
`remediationPlan(title: "…") { verification { … } }`, or split the request.

### AI answers need a signed-in caller, and have a rate limit of their own

**Affects you if** you publish a read-only instance (`API_ANONYMOUS_ROLE=viewer`) with an
AI key configured, or several people share one client address.

`/ai/*` asked only for the viewer role, which a public instance gives every visitor - so
the operator paid for anyone's questions. Anonymous callers now get 403 whenever auth is on,
and `aiEnabled` answers `false` to them, so the dashboard hides the AI features. Every
caller is also limited by `AI_RATE_PER_MIN` (default 10 per client per minute).

**Action:** sign in to use the AI features on a published instance. If a team reaches the
backend through one address, set `TRUSTED_PROXY_CIDRS` so each person is a client of their
own, or raise `AI_RATE_PER_MIN`.

---

## 1.18.0

### A Trivy scan of an image archive now reaches the merge gate

**Affects you if** you scan images from an archive - `docker save`, then
`trivy image --input image.tar` - and run the merge gate.

Trivy reports an archive scan under its file path, and a path matches no workload. The
image's libraries and CVEs arrived joined to nothing, the commit still counted as
analysed, and the gate answered **clean** on routes that ran through that image. The
collector now names the image by the tag the archive was saved with, which Trivy records
in the report, so those routes count.

**Action: none - but expect pull requests that used to pass to fail.** They were passing
because the scan was never connected to the workload, not because the change was safe.
An archive saved by image ID carries no tag and still cannot be joined; save it under the
reference you deploy (`docker save name:tag`), or scan the image by reference.

---

## 1.17.0

### The Kubernetes feed can now put a commit on the merge gate

**Affects you if** you post cluster dumps to `/ingest/k8s` *with* `?slug=&sha=`, and you
run the merge gate.

Those parameters used to be ignored by this collector: the gate blocks when a node on a
path carries the commit, and only the scanner feeds stamped one - so a pull request that
changed a manifest, which is how most routes open, could not turn the check red, while a
dependency bump could. The dump now stamps the objects it contains, so those routes count.

**Action: none, unless you were already sending those parameters.** If you were, and the
dump is a snapshot of the live cluster rather than what the pull request renders, the gate
will start attributing the whole snapshot to that commit. Drop the parameters for snapshot
feeds; keep them for `helm template` / `kustomize build` output of the commit under test.
Objects the dump only references (`cluster-admin`, a ServiceAccount named by a binding)
are never stamped.

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
