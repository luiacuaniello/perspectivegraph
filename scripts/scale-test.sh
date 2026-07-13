#!/usr/bin/env bash
#
# scale-test.sh - characterize the analyzer at a target graph size. It generates a large
# synthetic graph with genload, waits for the analyzer to complete a full pass over it,
# then reports the graph size and the per-pass timing measured from GET /metrics.
#
#   make scale-test                                   # default target size
#   SEEDS=128 WIDTH=1200 LAYERS=12 make scale-test    # bigger
#   ANALYZER_WORKERS=8 make scale-test                # (set on the backend) parallel pathfinding
#
# Requires the stack up (make up-full). See docs/SCALE.md for the methodology and knobs.
set -euo pipefail

SEEDS=${SEEDS:-64}
JEWELS=${JEWELS:-32}
LAYERS=${LAYERS:-10}
WIDTH=${WIDTH:-800}
FANOUT=${FANOUT:-4}
INGEST_URL=${INGEST_URL:-http://localhost:8081/ingest/events}
API_URL=${API_URL:-http://localhost:8080}
GO=${GO:-go}; export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.12}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "ERROR: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl not found"
curl -sf "$API_URL/healthz" >/dev/null 2>&1 || die "backend unreachable at $API_URL (run: make up-full)"

# Sum a metric's series (over labels) from the Prometheus text exposition.
metric() { curl -s "$API_URL/metrics" | awk -v m="$1" '$1 ~ "^"m"($|{)" {s+=$2} END{printf "%.3f", s+0}'; }
int()    { printf "%.0f" "$1"; }
avg()    { awk -v s="$1" -v c="$2" 'BEGIN{ if (c+0>0) printf "%.2f s", s/c; else printf "n/a" }'; }

echo "==> generating graph: seeds=$SEEDS jewels=$JEWELS layers=$LAYERS width=$WIDTH fanout=$FANOUT"
before_passes=$(int "$(metric perspectivegraph_analyzer_passes_total)")
before_pass_sum=$(metric perspectivegraph_analyzer_pass_seconds_sum)
before_pass_cnt=$(metric perspectivegraph_analyzer_pass_seconds_count)
before_pf_sum=$(metric perspectivegraph_analyzer_pathfind_seconds_sum)
before_pf_cnt=$(metric perspectivegraph_analyzer_pathfind_seconds_count)

t0=$(date +%s)
( cd "$ROOT/backend" && $GO run ./cmd/perspectivegraph genload \
    --url "$INGEST_URL" --seeds "$SEEDS" --jewels "$JEWELS" --layers "$LAYERS" --width "$WIDTH" --fanout "$FANOUT" ) \
  || die "genload failed"

echo "==> waiting for the analyzer to complete a full pass over the new graph..."
# Two passes past the pre-ingest count guarantees at least one pass that saw the whole graph.
until [ "$(int "$(metric perspectivegraph_analyzer_passes_total)")" -ge "$((before_passes + 2))" ]; do sleep 3; done
t1=$(date +%s)

nodes=$(int "$(metric perspectivegraph_analyzer_graph_nodes)")
edges=$(int "$(metric perspectivegraph_analyzer_graph_edges)")
paths=$(int "$(metric perspectivegraph_analyzer_critical_paths)")
pass_dsum=$(awk -v a="$(metric perspectivegraph_analyzer_pass_seconds_sum)" -v b="$before_pass_sum" 'BEGIN{printf "%.3f", a-b}')
pass_dcnt=$(awk -v a="$(metric perspectivegraph_analyzer_pass_seconds_count)" -v b="$before_pass_cnt" 'BEGIN{printf "%.0f", a-b}')
pf_dsum=$(awk -v a="$(metric perspectivegraph_analyzer_pathfind_seconds_sum)" -v b="$before_pf_sum" 'BEGIN{printf "%.3f", a-b}')
pf_dcnt=$(awk -v a="$(metric perspectivegraph_analyzer_pathfind_seconds_count)" -v b="$before_pf_cnt" 'BEGIN{printf "%.0f", a-b}')

cat <<EOF

  -- scale result --------------------------------
  graph:            $nodes nodes, $edges edges
  critical paths:   $paths
  avg pass time:    $(avg "$pass_dsum" "$pass_dcnt")   (over $pass_dcnt passes at this scale)
  avg pathfind:     $(avg "$pf_dsum" "$pf_dcnt")
  ingest -> ready:  $((t1 - t0)) s wall
  knobs:            ANALYZER_WORKERS=${ANALYZER_WORKERS:-auto}  ANALYZER_INCREMENTAL=${ANALYZER_INCREMENTAL:-false}
  ------------------------------------------------
EOF
