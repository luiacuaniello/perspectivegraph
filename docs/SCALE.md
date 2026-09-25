# Scale & performance

How PerspectiveGraph behaves as the graph grows, the knobs that matter, and how to measure
it on your own hardware and data. The numbers that matter are the ones you get from
`make scale-test` against your target size - this document is the method, not a benchmark
claim.

## What scales

The hot loop is the **analyzer pass**: fetch the graph, run per-seed pathfinding from every
internet-exposed node to every sensitive asset, score the paths, publish. Two knobs bound
its cost:

- **`ANALYZER_WORKERS`** - per-seed pathfinding parallelism. `0` (default) = one worker per
  CPU. The output is **byte-identical** regardless of the value; it only trades CPU for
  pass latency. Raise it on a multi-core host with a large seed set.
- **`ANALYZER_INCREMENTAL`** - keep the graph resident and patch it with each pass's delta
  instead of re-reading the whole thing. On a large Apache AGE graph the re-read dominates,
  so this is the fetch-cost win; it trades memory for fetch time. Off by default.

Secondary: `ANALYZER_MAX_HOPS` bounds path length (longer = more enumeration),
`ANALYZER_INTERVAL` sets how often a pass runs, and the store choice (in-memory vs AGE)
sets the fetch cost.

## Measure it

With the stack up (`make up-full`):

```bash
make scale-test                                  # default target size
SEEDS=128 WIDTH=1200 LAYERS=12 make scale-test   # a bigger graph
```

`scripts/scale-test.sh` generates a synthetic graph with `genload`, waits for the analyzer
to complete a full pass over it, and reports - measured from `/metrics` - the graph size,
the critical-path count, and the **per-pass** analyzer and pathfinding times (as a delta
over just the passes at that scale, so warm-up passes do not dilute the number).

To compare parallelism, run it twice with different `ANALYZER_WORKERS` on the backend and
compare `avg pass time`:

```bash
ANALYZER_WORKERS=1 docker compose --profile app up -d && make scale-test
ANALYZER_WORKERS=8 docker compose --profile app up -d && make scale-test
```

## Sample result

A reference point (single laptop, in-container AGE store, default workers) to show the shape
of the output - **not** a performance guarantee; run it on your hardware for numbers you can
trust:

```
$ SEEDS=40 JEWELS=24 LAYERS=8 WIDTH=500 FANOUT=4 make scale-test
genload: posted 4000 nodes + 14000 edges in 8 events (1731 KiB) -> 202 Accepted

  -- scale result --------------------------------
  graph:            4344 nodes, 2740 edges
  critical paths:   60
  avg pass time:    0.80 s   (over 2 passes at this scale)
  avg pathfind:     0.01 s
  ingest -> ready:  16 s wall
  knobs:            ANALYZER_WORKERS=auto  ANALYZER_INCREMENTAL=false
  ------------------------------------------------
```

(The resident graph is smaller than what `genload` posts because duplicate nodes merge,
and edges whose endpoints never arrive stay parked rather than landing - see
`perspectivegraph_graph_pending_edges`.)

## Writing an event

The analyzer is not the only cost that grows with the estate: every event is written to
the graph before anything can reason about it, and a large cluster or cloud account
arrives as one large event. Measured against the bundled Postgres + AGE on one laptop,
one event carrying a chain of containers (N nodes, N-1 edges), written to an empty graph
and then again unchanged - the second is what a connector pass does every fifteen
minutes:

| event | 1.18.1: first write / again | now: first write / again |
|---|---|---|
| 500 nodes, 499 edges | 2.0 s / 2.0 s | 0.95 s / 0.65 s |
| 2,000 nodes, 1,999 edges | 10.1 s / 11.0 s | 3.6 s / 2.6 s |
| 5,000 nodes, 4,999 edges | 36.4 s / 40.4 s | 9.8 s / 6.7 s |

Three things made the old column grow faster than the event:

- **A transaction per element.** Each node and edge paid BEGIN, the AGE setup, its
  statement and a COMMIT. An event is now one transaction.
- **An index nothing used.** Vertices were matched with `{id: …}`, which AGE turns into a
  containment test the per-label `id` index cannot serve, so every lookup scanned the
  label's table. They are matched with `WHERE n.id = …` now, which the index serves.
- **A plan chosen on stale statistics.** On a graph whose statistics predate the rows being
  written, the planner sorted the whole edge table for every edge. Writes now ask for
  nested loops over the indexes, which is always the right plan for a lookup by id.

At 36 seconds the 5,000-node event also outlasted the 30 seconds JetStream then waited
before handing it to another replica, which started writing the same nodes while the
first was still at it.

An event larger than one bus message - 1 MiB on a default NATS, about 6,000 nodes of a
typical cluster dump - is split into chunks, nodes first, and each chunk is written as
above. Chunks can land on different replicas in any order: an edge that arrives before
its endpoint is parked and lands in the write that brings it. Measured with two
replicas and a 1.5 MB report through the merge gate: two messages, 6,000 edges parked
and landed, 6,002 vertices, no duplicates, and the gate's verdict taken after the last
chunk.

## Simulating risk

Every analyzer pass runs a Monte Carlo simulation over the whole graph, and every fix's
verification runs two. On the genload graph above (4,000 nodes, 14,000 edges):

| simulation | 1.19 | now |
|---|---|---|
| 800 iterations, complete | 9.6 s | 2.8 s |
| 800 iterations, point estimate only (a fix's verification) | 9.6 s | 0.08 s |
| analyzer pass (2,000 iterations) | 10.4 s | 3.0 s |

A simulation "of 800 iterations" ran about 28,800 trials: the 800 asked for, 25,600 for
the credible band (64 × 400) and 2,400 for the attacker-profile mixture. A verification
reads only the point estimate, so it now skips the other two. The trials themselves
moved from string-keyed maps to integer indices, drawing the same random numbers in the
same order - every result is identical to the old code's, and a test holds them to it.

## How the cost grows

The sample above is one point. This is the shape, measured on the synthetic layered graph
(`BenchmarkFindCriticalPaths`, 64 seeds, 32 jewels, one laptop core count) so the growth is
comparable across sizes:

| graph | pathfinding pass | allocated per pass |
|---|---|---|
| 10k nodes / 45k edges | 241 ms | 48 MB |
| 25k nodes / 120k edges | 339 ms | 95 MB |
| 50k nodes / 245k edges | 560 ms | 180 MB |
| 100k nodes / 495k edges | 1.27 s | 349 MB |

Ten times the graph costs about 5.3x the time: **sub-linear in nodes**, because the work is
per-seed Dijkstra over a sparse graph rather than anything quadratic. Memory grows roughly
linearly with edges. These are pathfinding numbers only - on Apache AGE the graph *fetch*
usually dominates a pass at these sizes, which is what `ANALYZER_INCREMENTAL` addresses.

Reproduce with `go test ./internal/analyzer -bench FindCriticalPaths -benchmem`.

## Sizing the backend

Requests and limits derived from the table above, not guessed. The allocation figure is
per pass and transient, so the memory request is roughly "resident graph plus one pass"
and the limit leaves room for a pass that arrives while the previous one is still being
collected:

| graph | requests | limits |
|---|---|---|
| up to 10k nodes | `cpu: 250m`, `memory: 512Mi` | `memory: 1Gi` |
| up to 50k nodes | `cpu: 500m`, `memory: 1Gi` | `memory: 2Gi` |
| up to 100k nodes | `cpu: 1`, `memory: 2Gi` | `memory: 4Gi` |

Three notes that matter more than the numbers:

- **Set something.** The chart default is `resources: {}`, which is BestEffort QoS: the
  kubelet evicts that pod first under node pressure, and an analyzer pass over a large
  graph is exactly the memory spike that creates the pressure. `values-production.yaml`
  sets the 10k row; raise it from there.
- **No CPU limit.** Throttling an analyzer pass only makes it longer, and a pass that
  overruns `ANALYZER_INTERVAL` is the failure this table exists to avoid. Request CPU so
  the scheduler reserves it; do not cap it.
- **`ANALYZER_INCREMENTAL` trades memory for fetch time**, so it moves you up a row
  rather than down one: the graph stays resident between passes.

These are a starting point measured on a synthetic layered graph. Run `make scale-test`
against your own size and shape before treating them as more than that.

## Scaling out (replicas)

The compute path is already replica-safe, and the governance path is not. Both halves of
that sentence matter:

- **Reads and analysis scale horizontally.** Every replica computes attack paths locally and
  serves its own API reads. Work is not duplicated where it would be harmful, because
  at-most-once side effects - drift webhooks, PR/MR comments, connector collection - are
  gated behind a **leader election** (`internal/leader`): a PostgreSQL *session-scoped*
  advisory lock, so if the leader dies its connection drops, the lock releases, and another
  replica takes over on its next check. No external coordinator. This is active whenever the
  store backend is `apache-age`.
- **Graph writes converge.** Replicas share one consumer, so two events that name the
  same asset are written at the same time. AGE has no unique constraint: before this was
  locked, eight concurrent writers of the same fifty nodes left between ten and
  twenty-four duplicate vertices, and the first write of a new label failed when two
  replicas raced to create its table. Each write now holds a transaction-scoped advisory
  lock on its tenant's graph - transaction-scoped, so it works through a PgBouncer in
  transaction mode, unlike the leader election above. Readers never take it.
- **The governance stores can live in the database.** `GOVERNANCE_BACKEND=postgres`
  moves **suppressions, tickets, posture history, red-team validations and the KEV
  holdout** into PostgreSQL, where every replica reads the same rows. The schema is
  created and upgraded on startup under an advisory lock, so replicas starting together
  during a rolling update cannot collide, and a release rolled back onto a database a
  newer one migrated refuses to start rather than writing a schema it does not
  understand.
- **The audit log follows them.** It is a tamper-evident hash chain, so it could not be
  moved by repeating the same port: two replicas reading the same tail would both claim
  it as `prev_hash` and fork the chain, after which `Verify` reports tampering on a log
  nobody touched. Under `GOVERNANCE_BACKEND=postgres` each append instead takes a
  transaction-scoped advisory lock, reads the tail and writes inside that transaction, so
  every replica appends to **one** chain. The file backend is the single-writer one: with
  `AUDIT_LOG_PATH` and no governance database, keep `backend.replicas: 1`.

In practice: with `GOVERNANCE_BACKEND=postgres`, run N replicas against a shared AGE -
every replica reads the same governance rows and appends to the same audit chain, and the
leader election keeps the side effects at once each. On the file backend, stay at one
replica.

`values-ha.yaml` is that shape ready to apply, as an overlay on the production profile:
it sets both, raises the replicas, spreads them across nodes and adds a disruption budget
(see [OPERATIONS §7](OPERATIONS.md#7-high-availability)).

The chart holds that line for you. `persistence.enabled` with more than one replica
**fails to render**, and the message names the reason it is refusing: on the file backend
the stores would split-brain, and on the Postgres backend the PVC holds nothing yet its
ReadWriteOnce mode still pins every pod to one node. So the Kubernetes recipe for
replicas is `governanceBackend: postgres` **and** `persistence.enabled: false` - and
nothing is given up, because the chain moved into the database rather than being dropped.

## Interpreting it

- **`avg pass time` approaching `ANALYZER_INTERVAL`**: passes are starting to overlap. Raise
  `ANALYZER_WORKERS`, or lengthen the interval if near-real-time is not required.
- **Fetch-dominated on AGE (large graph, pathfind time small vs pass time)**: turn on
  `ANALYZER_INCREMENTAL` so a pass patches the resident graph instead of re-reading it.
- **Pathfind-dominated (deep/wide graph)**: raise `ANALYZER_WORKERS` up to the core count;
  consider a lower `ANALYZER_MAX_HOPS` if paths beyond N hops are not actionable.
- **Database**: for a production-size graph use an external, resourced Postgres+AGE - which
  on AWS and GCP means one you run yourself, since only Azure offers AGE as a managed
  service ([OPERATIONS.md §3](OPERATIONS.md#3-the-database-postgresql--apache-age) has the
  matrix). The bundled demo database is not sized for scale.

The `PerspectiveGraphAnalyzerPassSlow` alert (see
[deploy/observability](../deploy/observability)) fires when p95 pass time crosses the
threshold, so this stays visible in production without re-running the harness.
