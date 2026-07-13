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

## Interpreting it

- **`avg pass time` approaching `ANALYZER_INTERVAL`**: passes are starting to overlap. Raise
  `ANALYZER_WORKERS`, or lengthen the interval if near-real-time is not required.
- **Fetch-dominated on AGE (large graph, pathfind time small vs pass time)**: turn on
  `ANALYZER_INCREMENTAL` so a pass patches the resident graph instead of re-reading it.
- **Pathfind-dominated (deep/wide graph)**: raise `ANALYZER_WORKERS` up to the core count;
  consider a lower `ANALYZER_MAX_HOPS` if paths beyond N hops are not actionable.
- **Database**: for a production-size graph use an external, resourced managed Postgres+AGE
  (see [OPERATIONS.md](OPERATIONS.md)); the bundled demo database is not sized for scale.

The `PerspectiveGraphAnalyzerPassSlow` alert (see
[deploy/observability](../deploy/observability)) fires when p95 pass time crosses the
threshold, so this stays visible in production without re-running the harness.
