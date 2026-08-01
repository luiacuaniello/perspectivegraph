#!/usr/bin/env bash
# Statement-coverage gate for the library packages.
#
# Two details decide whether the number this prints is true, and both are easy to get
# wrong:
#
#   1. -coverpkg=./... . `go test ./...` credits coverage ONLY to the package under
#      test. internal/graph/age is driven through the graph.Store interface by the
#      contract test in internal/graph, so without -coverpkg it reported 6.6% while it
#      was really 67.6%. The flag makes every package's statements attributable no
#      matter which test exercised them - at the cost of each package emitting a profile
#      covering all of them, so the blocks have to be deduplicated (below) or the totals
#      are counted once per package and the result is nonsense.
#
#   2. cmd/ is excluded. It is main() plus the CLI subcommands - process wiring, whose
#      tests would assert that the program starts rather than that anything works. The
#      threshold is about the engine, so it is measured on internal/ and pkg/. The
#      command's own number is printed for visibility, never enforced.
#
# Usage: scripts/coverage-gate.sh [minimum-percent]   (default 80)
set -euo pipefail

MIN="${1:-80}"
cd "$(dirname "$0")/../backend"

profile="$(mktemp -t pg-cover.XXXXXX)"
trap 'rm -f "$profile"' EXIT

echo "→ running tests with cross-package coverage attribution…"
GOTOOLCHAIN="${GOTOOLCHAIN:-go1.25.12}" CGO_ENABLED=0 \
  go test ./... -coverpkg=./... -coverprofile="$profile" -timeout 900s >/dev/null

awk -v min="$MIN" '
NR > 1 {
  # key is file:startLine.startCol,endLine.endCol - the same block appears once per
  # package profile, so keep its statement count and the HIGHEST hit count seen.
  st[$1] = $2
  if ($3 + 0 > hit[$1]) hit[$1] = $3 + 0
}
END {
  for (k in st) {
    split(k, a, ":")
    if (a[1] ~ /\/cmd\//) { ctot += st[k]; if (hit[k] == 0) cunc += st[k]; continue }
    tot += st[k]; if (hit[k] == 0) unc += st[k]
  }
  lib = (tot - unc) * 100 / tot
  cmdpct = ctot ? (ctot - cunc) * 100 / ctot : 0
  printf "\n  libraries (internal/ + pkg/): %.1f%%  (%d of %d statements uncovered)\n", lib, unc, tot
  printf "  cmd/ (not enforced):          %.1f%%  (%d of %d)\n\n", cmdpct, cunc, ctot
  if (lib + 0 < min + 0) {
    printf "  FAIL: library coverage %.1f%% is below the %s%% gate\n", lib, min
    exit 1
  }
  printf "  OK: library coverage %.1f%% meets the %s%% gate\n", lib, min
}' "$profile"
