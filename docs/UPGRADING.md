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
