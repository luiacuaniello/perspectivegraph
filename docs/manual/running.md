# Running it: freshness, backup and scaling

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Keeping the graph fresh, backing it up and restoring it, and scaling the analyzer.

## Operating it: freshness, backup & DR

A correlation engine that only *adds* drifts toward fiction: a pod is deleted, a
security group is torn down, but the path through it lingers and gets reported
forever. Three things keep the graph honest over time.

- **Complete snapshots (`GRAPH_SWEEP`, on by default).** The engine records who said
  each node and edge exists: the source, and the scope when the source described that
  scope in full. When a complete snapshot of a scope has landed - every message of the
  ingest, however it was split - whatever the same source said about that scope before
  and did not say again is withdrawn. An element leaves the graph only when *no* source
  asserts it any more. So a CVE fixed in an image disappears at the image's next scan,
  and an instance terminated at the next AWS pull, instead of lingering for a TTL.

  Who declares a snapshot complete is whoever can vouch for it:

  | Source | Complete for | When |
  |---|---|---|
  | Trivy | the image (`image:<ref>`, registry-normalized) | scanned by reference, something scanned, no PR context |
  | Semgrep | the repository (`repository:<repo>`) | `?repo=` given, no analysis errors, no PR context |
  | AWS connector | IAM: the account; network: the account and region | the feed was read without error and the account is known |
  | anything else | the scope you name with `?snapshot=<scope>` | you sent the whole scope |

  Five safeguards, because this is the one part of the engine that deletes:

  - A pull request's scan never retracts: it describes a change that may never run.
  - Nothing is retracted until the *whole* ingest has reached the graph, and exactly
    one replica applies it. A batch that never completes - a message dead-lettered -
    retracts nothing.
  - An older snapshot that lands after a newer one retracts nothing the newer one said.
  - An edge another source still asserts, joined to a node that was removed, is parked
    rather than lost, and lands again if the node comes back.
  - Elements already in the graph when you upgrade to 1.23 were never attributed to a
    source, so no snapshot takes them. `GRAPH_TTL` still can, as it can anything.

  A scan filtered by severity is complete only for its filter: if two pipelines feed
  the same image differently, send the filtered one with `?snapshot=none`. Visibility:
  a log line per snapshot that removed something, and
  `perspectivegraph_graph_swept_total{kind="node|edge|parked"}` and
  `perspectivegraph_graph_sweeps_total{source,result}`. `GRAPH_SWEEP=false` (Helm
  `graph.sweep: false`) keeps everything until `GRAPH_TTL`, as before 1.23.

- **Staleness pruning (`GRAPH_TTL`).** Every node and edge is stamped with a
  `last_seen` time on each observation. When `GRAPH_TTL` is set, the analyzer
  (leader-only, on a derived cadence ≈ TTL/6) removes anything not re-observed
  within the window, so a **departed asset stops generating phantom paths**.
  Pruning a node detaches its edges; elements that predate the stamp are
  *grandfathered* (never pruned) so turning the feature on can't wipe legacy
  data. It's off by default (the one-shot demo would prune itself); set it to a
  few feed-cycles in production:

  ```bash
  GRAPH_TTL=168h make run-backend      # 7 days; assets unseen for a week are dropped
  ```

  Visibility: the dashboard footer shows *“pruned N stale”*, the GraphQL
  `status { prunedNodes prunedEdges lastPrunedAt }` exposes the totals, and
  Prometheus has `perspectivegraph_graph_pruned_{nodes,edges}_total`.

- **The graph is *derived* state - that's your DR story.** Everything in
  Postgres+AGE is reconstructible by re-ingesting the source feeds, so a lost
  database is a *re-seed*, not a data-loss event. Back up Postgres for history
  and convenience (`pg_dump` of the AGE-extended database, or a managed
  Postgres's PITR/replica); restore, or just re-run the collectors, to recover.
  For HA, run Postgres as a managed/replicated service (the chart can point at an
  external one) - the backend is stateless and horizontally scalable, and
  leader election already ensures only one replica fires side-effects.

### Scaling the analyzer

The per-pass cost stays flat as the graph grows, with three layers you can tune:

- **Change-detection (always on).** A pass is skipped entirely when nothing was
  written since the last one - a steady graph costs almost nothing.
- **Parallel pathfinding (on by default).** Each internet-exposed entry point gets
  an independent shortest-path search, fanned out across `ANALYZER_WORKERS`
  goroutines (default = number of CPUs). The result is identical regardless of
  worker count, so it's a pure speedup - ~2.9× at 8 workers on a 10k-node /
  64-seed benchmark (`make bench`).
- **Incremental snapshotting (opt-in, `ANALYZER_INCREMENTAL=true`).** Instead of
  re-reading the whole graph each pass, the analyzer keeps it resident and patches
  it with just what changed since the last pass (filtered on the same `last_seen`
  the pruner uses, so only the changed slice leaves Postgres). It still recomputes
  all paths, but skips the dominant fetch cost on a large AGE graph; a full re-read
  self-heals the cache on the first pass, after a prune, and periodically. It trades
  memory for fetch cost, so it's off by default.

  ```bash
  ANALYZER_WORKERS=8 ANALYZER_INCREMENTAL=true make run-backend
  ```

  Scale visibility on `/metrics`: graph size (`perspectivegraph_analyzer_graph_{nodes,edges}`),
  snapshot mode (`..._snapshots_total{mode="full|delta"}`), and pathfinding latency
  (`..._pathfind_seconds`). To load-test end-to-end, post a large synthetic attack
  surface with `make seed-load` (or `perspectivegraph genload --seeds 64 --width 1000 …`).

> **On Apache AGE (an honest caveat).** AGE is a younger, less battle-tested
> extension than core Postgres. PerspectiveGraph de-risks leaning on it: node and
> edge analysis runs over an in-process snapshot by default (the DB is storage,
> not the query engine, unless you opt into `ANALYZER_DB_PATHS`), the in-memory
> and AGE stores are held to one shared contract-test suite, and `GRAPH_STRICT`
> makes a misconfigured DB fail loudly. Because the graph is rebuildable, an AGE
> issue is an availability concern, not a correctness or data-durability one.
