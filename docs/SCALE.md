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

(The resident graph is smaller than what `genload` posts because dangling edges - whose
endpoints have not arrived yet - are rejected and redelivered, and duplicate nodes merge.)

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
