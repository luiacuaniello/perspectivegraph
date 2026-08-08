package andprobe

import "strings"

import "testing"

// The thresholds ARE the decision this tool exists to give, so they are asserted at the
// boundaries rather than in the middle of each band - a band that quietly shifted would
// tell somebody to build a Bayesian attack graph for an estate where it changes nothing,
// or to skip one where it would have paid.
func TestVerdictBands(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frac       float64
		candidates int
		want       string
	}{
		{"no candidates at all", 0.9, 0, "or-dominated"},
		{"just below the first band", 0.099, 5, "or-dominated"},
		{"exactly at the first band", 0.1, 5, "some AND"},
		{"inside the middle band", 0.39, 5, "some AND"},
		{"exactly at the second band", 0.4, 5, "AND semantics is common"},
		{"well above", 0.95, 50, "AND semantics is common"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Verdict(tc.frac, tc.candidates)
			if !strings.Contains(got, tc.want) {
				t.Errorf("frac=%v candidates=%d gave %q, want a verdict containing %q",
					tc.frac, tc.candidates, got, tc.want)
			}
		})
	}
}

// Zero candidates must win over any fraction: a fraction computed from nothing is not a
// measurement, and reporting "AND is common" from an empty sample is how a decision tool
// sends someone off to build something on the strength of no evidence.
func TestNoCandidatesOverridesTheFraction(t *testing.T) {
	if got := Verdict(1.0, 0); !strings.Contains(got, "or-dominated") {
		t.Fatalf("frac=1.0 with zero candidates gave %q", got)
	}
}

// Whatever the numbers, the answer must keep telling the reader to confirm against real
// verdicts. This tool measures shape, not truth.
func TestEveryVerdictStillAsksForConfirmation(t *testing.T) {
	for _, frac := range []float64{0.0, 0.2, 0.9} {
		got := Verdict(frac, 10)
		if !strings.Contains(got, "verdicts") && !strings.Contains(got, "calibration") {
			t.Errorf("frac=%v gave %q, which reads as a conclusion rather than a measurement", frac, got)
		}
	}
}
