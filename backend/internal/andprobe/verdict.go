// Package andprobe turns a measurement of the graph into the decision it exists to
// inform: whether modelling AND-semantics (a compromise needing several prerequisites at
// once) would add signal, or whether the estate is pure OR-reachability and the work
// would be a no-op.
//
// The thresholds live here rather than inside the subcommand because they ARE the
// decision. A tool that answers "build it" on an estate where it changes nothing costs
// somebody a quarter.
package andprobe

// Verdict reports what the measured fraction of AND-candidate paths implies.
func Verdict(frac float64, candidates int) string {
	switch {
	case candidates == 0 || frac < 0.1:
		return "or-dominated - #6 BAG is likely a NO-OP here; invest in better p(e) (calibration, κ-from-evidence-counts) instead"
	case frac < 0.4:
		return "some AND candidates - #6 may add signal on a minority of paths; confirm with real refuted verdicts before building"
	default:
		return "AND semantics is common - #6 BAG (as Monte-Carlo-over-BAG) would likely add real signal; still confirm with verdicts"
	}
}
