package validation

import (
	"context"
	"math"
	"math/rand/v2"
	"testing"
)

func pairsOf(pos, neg []float64) []rankPair {
	out := make([]rankPair, 0, len(pos)+len(neg))
	for _, s := range pos {
		out = append(out, rankPair{score: s, y: 1})
	}
	for _, s := range neg {
		out = append(out, rankPair{score: s, y: 0})
	}
	return out
}

func repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// bruteAUC is the definition, not an algorithm: over every (confirmed, refuted) pair,
// count 1 when the confirmed one scores higher and 1/2 on a tie.
func bruteAUC(pairs []rankPair) float64 {
	var wins float64
	pos, neg := 0, 0
	for _, a := range pairs {
		if a.y == 1 {
			pos++
		} else if a.y == 0 {
			neg++
		}
	}
	for _, a := range pairs {
		if a.y != 1 {
			continue
		}
		for _, b := range pairs {
			if b.y != 0 {
				continue
			}
			switch {
			case a.score > b.score:
				wins++
			case a.score == b.score:
				wins += 0.5
			}
		}
	}
	return wins / (float64(pos) * float64(neg))
}

func TestAUCWithATieByHand(t *testing.T) {
	// Pairs: 0.9>0.5, 0.9>0.1, 0.5=0.5 (half), 0.5>0.1 - 3.5 of 4.
	d := discriminationOf(pairsOf([]float64{0.9, 0.5}, []float64{0.5, 0.1}))
	if !d.HasData || d.AUC != 0.875 {
		t.Fatalf("AUC = %v (has_data %v), want exactly 0.875", d.AUC, d.HasData)
	}
}

// The rank method must agree with the pairwise definition to the bit, not within a
// tolerance: both sum half-integers, which float64 holds exactly. Scores are drawn from a
// coarse grid so ties are the common case rather than the exception.
func TestAUCMatchesThePairwiseDefinitionExactly(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 300; trial++ {
		n := 2 + rng.IntN(60)
		pairs := make([]rankPair, n)
		for i := range pairs {
			pairs[i] = rankPair{score: float64(rng.IntN(11)) / 10, y: float64(rng.IntN(2))}
		}
		auc, _, pos, neg := aucMidRank(pairs)
		if pos == 0 || neg == 0 {
			continue
		}
		if want := bruteAUC(pairs); auc != want {
			t.Fatalf("trial %d: mid-rank AUC %v != pairwise %v", trial, auc, want)
		}
	}
}

// Two backends hand the same evidence over in different orders. The number published has
// to be the same bits either way, or "how well does the order work" depends on storage.
func TestAUCDoesNotDependOnInputOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	pairs := make([]rankPair, 80)
	for i := range pairs {
		pairs[i] = rankPair{score: float64(rng.IntN(7)) / 6, y: float64(rng.IntN(2))}
	}
	first := discriminationOf(pairs)
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(pairs), func(a, b int) { pairs[a], pairs[b] = pairs[b], pairs[a] })
		if got := discriminationOf(pairs); got != first {
			t.Fatalf("shuffle %d changed the result:\n  %+v\n  %+v", i, got, first)
		}
	}
}

func TestPerfectSeparationDiscriminatesWithoutAZeroWidthInterval(t *testing.T) {
	d := discriminationOf(pairsOf(repeat(0.9, 10), repeat(0.1, 10)))
	if d.AUC != 1 || d.Verdict != "discriminates" {
		t.Fatalf("AUC %v verdict %q, want 1 and discriminates", d.AUC, d.Verdict)
	}
	// The raw Hanley-McNeil error is zero here. Ten against ten proves separation, not
	// that the true AUC is exactly 1.00 - the interval must say so.
	if d.AUCLow >= 1 {
		t.Fatalf("interval [%v, %v] has zero width at n=10/10 - precision the sample cannot support", d.AUCLow, d.AUCHigh)
	}
	if d.AUCLow <= 0.5 {
		t.Fatalf("interval lower bound %v reaches chance; perfect 10/10 separation should not", d.AUCLow)
	}
}

func TestInvertedOrderIsReportedAsInverted(t *testing.T) {
	d := discriminationOf(pairsOf(repeat(0.1, 10), repeat(0.9, 10)))
	if d.AUC != 0 || d.Verdict != "inverted" {
		t.Fatalf("AUC %v verdict %q, want 0 and inverted", d.AUC, d.Verdict)
	}
}

func TestAllTiedIsIndistinguishableFromChance(t *testing.T) {
	d := discriminationOf(pairsOf(repeat(0.5, 12), repeat(0.5, 12)))
	if d.AUC != 0.5 || d.Verdict != "indistinguishable-from-chance" {
		t.Fatalf("AUC %v verdict %q, want 0.5 and indistinguishable-from-chance", d.AUC, d.Verdict)
	}
}

// Partial is half credit to a scoring rule, but not a class to a ranking comparison.
func TestPartialVerdictsDoNotEnterTheAUC(t *testing.T) {
	base := pairsOf([]float64{0.9, 0.7, 0.6}, []float64{0.4, 0.8})
	with := append(append([]rankPair(nil), base...), rankPair{0.95, 0.5}, rankPair{0.05, 0.5})
	a, b := discriminationOf(base), discriminationOf(with)
	if a != b {
		t.Fatalf("partials changed the result:\n  without %+v\n  with    %+v", a, b)
	}
}

func TestOneClassHasNoAUC(t *testing.T) {
	d := discriminationOf(pairsOf(repeat(0.9, 30), nil))
	if d.HasData || d.Verdict != "insufficient-data" || d.Positives != 30 {
		t.Fatalf("%+v: an AUC needs both classes", d)
	}
}

// Below the per-class floor the number is shown but not judged, like calibration.
func TestBelowThePerClassFloorTheAUCIsShownButNotJudged(t *testing.T) {
	d := discriminationOf(pairsOf(repeat(0.9, 30), []float64{0.1}))
	if !d.HasData || d.AUC != 1 {
		t.Fatalf("%+v: the raw AUC should still be reported", d)
	}
	if d.Verdict != "insufficient-data" {
		t.Fatalf("verdict %q from a single refuted verdict - that is the rank of one point", d.Verdict)
	}
}

func TestNonFiniteScoresAreSkipped(t *testing.T) {
	base := pairsOf([]float64{0.9, 0.7}, []float64{0.2, 0.3})
	with := append(append([]rankPair(nil), base...), rankPair{math.NaN(), 1}, rankPair{math.Inf(1), 0})
	if a, b := discriminationOf(base), discriminationOf(with); a != b {
		t.Fatalf("a NaN or Inf score changed the result:\n  %+v\n  %+v", a, b)
	}
}

// ── wiring through the calibration report ──────────────────────────────────────

func putRec(t *testing.T, s *Store, r Record) {
	t.Helper()
	r.Tenant, r.Source = "acme", "test"
	if _, err := s.Put(context.Background(), r); err != nil {
		t.Fatalf("put %+v: %v", r, err)
	}
}

func prio(v float64) *float64 { return &v }

// A 0.0 Priority is a real, weak priority - and the refuted paths at the bottom of the
// order are exactly what the metric needs. Treating it as "not captured" would drop them.
func TestAZeroPriorityIsEvidenceNotAbsence(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 10; i++ {
		putRec(t, s, Record{PathID: "hi" + string(rune('a'+i)), Outcome: Confirmed, PredictedScore: 0.5, PredictedPriority: prio(80)})
		putRec(t, s, Record{PathID: "lo" + string(rune('a'+i)), Outcome: Refuted, PredictedScore: 0.5, PredictedPriority: prio(0)})
	}
	cal, _ := s.Calibration(context.Background(), "acme")
	pd := cal.PriorityDiscrimination
	if pd == nil || pd.Negatives != 10 {
		t.Fatalf("priority discrimination %+v: the ten 0.0-priority refuted verdicts were dropped", pd)
	}
	if pd.AUC != 1 || pd.Verdict != "discriminates" {
		t.Fatalf("priority discrimination %+v, want a perfect order", pd)
	}
	// S(P) is identical for all twenty, so the score itself orders nothing.
	if cal.Discrimination.AUC != 0.5 {
		t.Fatalf("score AUC %v with every score equal, want 0.5", cal.Discrimination.AUC)
	}
}

func TestPriorityIsGradedOnlyOnThePathTrack(t *testing.T) {
	s := newStore(t)
	putRec(t, s, Record{PathID: "t1", Scope: ScopeTarget, Outcome: Confirmed, PredictedCompromise: 0.7, PredictedPriority: prio(90)})
	putRec(t, s, Record{PathID: "t2", Scope: ScopeTarget, Outcome: Refuted, PredictedCompromise: 0.2, PredictedPriority: prio(10)})
	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.PriorityDiscrimination != nil {
		t.Fatalf("target-scoped verdicts graded the path order: %+v", cal.PriorityDiscrimination)
	}
	if cal.Target == nil || cal.Target.PriorityDiscrimination != nil {
		t.Fatal("the target track must never carry a priority discrimination")
	}
	if !cal.Target.Discrimination.HasData {
		t.Fatalf("target track discrimination %+v: its own score should be graded", cal.Target.Discrimination)
	}
}

func TestUncapturedPriorityLeavesTheOrderUngraded(t *testing.T) {
	s := newStore(t)
	put(t, s, "a", Confirmed, 0.8)
	put(t, s, "b", Refuted, 0.2)
	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.PriorityDiscrimination != nil {
		t.Fatalf("no verdict carried a Priority, yet the order was graded: %+v", cal.PriorityDiscrimination)
	}
}

// Calibration withholds its reads below eight samples. Discrimination has its own floor
// and must still report - otherwise a thin calibration dataset would hide the ranking.
func TestDiscriminationIsReportedBelowTheCalibrationFloor(t *testing.T) {
	s := newStore(t)
	put(t, s, "a", Confirmed, 0.9)
	put(t, s, "b", Refuted, 0.1)
	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.Samples >= minCalibrationSamples {
		t.Fatalf("test needs a dataset below the calibration floor, has %d", cal.Samples)
	}
	if !cal.Discrimination.HasData || cal.Discrimination.AUC != 1 {
		t.Fatalf("discrimination %+v was hidden by the calibration floor", cal.Discrimination)
	}
}

func TestANilStoreReportsAWellFormedDiscrimination(t *testing.T) {
	var s *Store
	cal, err := s.Calibration(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if cal.Discrimination.Verdict != "insufficient-data" || cal.Discrimination.HasData {
		t.Fatalf("nil store discrimination %+v", cal.Discrimination)
	}
}
