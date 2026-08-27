#!/usr/bin/env bash
# Run one fuzz target and tell a real finding apart from the clock running out.
#
# `go test -fuzz` does not distinguish the two in its exit code. When -fuzztime expires
# the run can exit NON-ZERO with "context deadline exceeded" even though nothing was
# found - see golang/go#72104 - which turns every scheduled fuzz run into a red build
# and trains people to ignore the one signal that matters. It is likeliest on a small
# runner, where the coordinator competes with its own workers for CPU: a failing run
# shows long stretches of 0 execs/sec, then the counter jumping by six figures at once,
# which is a starved coordinator rather than a slow input.
#
# The reliable discriminator is not the error text, it is whether Go wrote a reproducer.
# A crash always leaves one under testdata/fuzz/<Target>/; a clean expiry never does.
# So: crasher present -> fail loudly and keep it for the artifact upload. No crasher and
# a deadline message -> the target survived its whole budget, which is a pass. Anything
# else -> fail, because an unrecognised failure is exactly what must not be swallowed.
#
# Usage: scripts/fuzz-target.sh <FuzzName> [fuzztime] [parallel]
set -uo pipefail

TARGET="${1:?usage: fuzz-target.sh <FuzzName> [fuzztime] [parallel]}"
FUZZTIME="${2:-3m}"
# Fewer workers than the default (one per CPU) on purpose: the coordinator needs a core
# too, and on a 2-vCPU runner four workers are what starve it into missing the shutdown.
PARALLEL="${3:-2}"

cd "$(dirname "$0")/../backend"
PKG=./internal/ingestion/fuzz
CORPUS="internal/ingestion/fuzz/testdata/fuzz/${TARGET}"

log="$(mktemp -t pg-fuzz.XXXXXX)"
trap 'rm -f "$log"' EXIT

echo "→ fuzzing ${TARGET} for ${FUZZTIME} with ${PARALLEL} workers…"
GOTOOLCHAIN="${GOTOOLCHAIN:-go1.25.13}" CGO_ENABLED=0 \
  go test "$PKG" -run '^$' -fuzz "^${TARGET}\$" -fuzztime "$FUZZTIME" -parallel "$PARALLEL" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"

if [ "$status" -eq 0 ]; then
  echo "  ${TARGET}: clean run."
  exit 0
fi

# A reproducer on disk means the fuzzer actually found something. That is the finding
# the weekly run exists to produce, and it must stay red.
if [ -d "$CORPUS" ] && [ -n "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
  echo ""
  echo "  ${TARGET}: FAILED with a reproducer - a real finding, kept for the artifact upload:"
  ls -l "$CORPUS" | sed 's/^/    /'
  exit 1
fi

# No reproducer. If Go merely ran out of budget, the target survived everything thrown
# at it, which is the outcome we wanted.
if grep -q "context deadline exceeded" "$log"; then
  echo ""
  echo "  ${TARGET}: -fuzztime (${FUZZTIME}) expired with no reproducer written."
  echo "  Treating as a pass: the target survived its whole budget. See golang/go#72104 -"
  echo "  go test -fuzz can exit non-zero on a clean timeout."
  exit 0
fi

# Failed, no deadline message, no reproducer on disk. The common case is a failure on
# the SEED corpus: Go writes no testdata entry for an input that is already a seed, so
# the crasher check above cannot see it. Whatever it is, it is not the clock running
# out, so it fails - this script only ever swallows the one case it can prove is benign.
echo ""
echo "  ${TARGET}: FAILED (exit ${status}) with no reproducer written and no deadline message."
echo "  Most likely a failure on the seed corpus, which leaves no testdata entry. Treating"
echo "  it as a real finding - read the log above."
exit "$status"
