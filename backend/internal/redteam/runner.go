package redteam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// Source labels verdicts this harness produces, so they are auditable and separable
// from human red-team or BAS-tool verdicts in the store.
const Source = "redteam-oracle"

// Attempt walks a path hop by hop, asking the oracle to settle each hop's assertion,
// and returns the verdict as a validation.Record ready for the calibration flywheel.
// The aggregation is deliberately strict, so the resulting calibration is trustworthy:
//
//	any hop Denied                         -> Refuted  (surfaced, but reality blocks it)
//	every hop Testable and Allowed         -> Confirmed (proven end-to-end)
//	otherwise (an untestable/inconclusive
//	           hop, with no denial)         -> Partial  (could not prove or disprove)
//
// PredictedScore is captured from the path itself (its S(P)), so the verdict pairs the
// model's prediction with reality's outcome - the pairing that makes it calibration
// data. The clock is injectable for deterministic tests.
func Attempt(ctx context.Context, o Oracle, p analyzer.AttackPath, tenant string, now time.Time) (validation.Record, error) {
	assertions := assertionsFor(p)

	testable, allowed := 0, 0
	var firstDenied *Assertion
	var deniedEvidence string
	var notes []string

	for i := range assertions {
		a := assertions[i]
		if !a.Testable {
			notes = append(notes, fmt.Sprintf("%s: inconclusive (%s)", a.Key(), a.Note))
			continue
		}
		testable++
		res, err := o.Check(ctx, a)
		if err != nil {
			return validation.Record{}, fmt.Errorf("oracle check %s: %w", a.Key(), err)
		}
		switch res.Decision {
		case Allowed:
			allowed++
			notes = append(notes, fmt.Sprintf("%s: allowed (%s)", a.Key(), res.Evidence))
		case Denied:
			if firstDenied == nil {
				firstDenied = &assertions[i]
				deniedEvidence = res.Evidence
			}
			notes = append(notes, fmt.Sprintf("%s: DENIED (%s)", a.Key(), res.Evidence))
		default:
			notes = append(notes, fmt.Sprintf("%s: inconclusive (%s)", a.Key(), res.Evidence))
		}
	}

	outcome := aggregate(len(assertions), testable, allowed, firstDenied != nil)

	evidence := strings.Join(notes, "; ")
	if firstDenied != nil {
		evidence = fmt.Sprintf("reality blocked hop %s: %s | %s", firstDenied.Key(), deniedEvidence, evidence)
	}

	return validation.Record{
		PathID:         p.ID,
		Tenant:         tenant,
		Outcome:        outcome,
		Scope:          validation.ScopePath,
		Source:         Source,
		Evidence:       evidence,
		Route:          routeOf(p),
		PredictedScore: p.Score,
		Hops:           len(p.Steps),
		CorrelatedHops: p.CorrelatedHops,
		WeightBasis:    weakestBasis(p),
		TestedAt:       now,
	}, nil
}

// aggregate applies the verdict rule. A path with no testable hops at all cannot be
// confirmed - there is nothing reality signed off on - so it is Partial.
func aggregate(total, testable, allowed int, anyDenied bool) validation.Outcome {
	switch {
	case anyDenied:
		return validation.Refuted
	case testable == total && testable > 0 && allowed == testable:
		return validation.Confirmed
	default:
		return validation.Partial
	}
}

// weakestBasis is the basis of the path's least-evidenced hop, the provenance class
// calibration recalibrates the path under (a path is only as trustworthy as its
// weakest hop). Mirrors the server-side capture so oracle verdicts segment the same
// way human ones do.
func weakestBasis(p analyzer.AttackPath) string {
	basis, best := "", 2.0
	for _, st := range p.Steps {
		if st.WeightBasis != "" && st.WeightConfidence < best {
			basis, best = st.WeightBasis, st.WeightConfidence
		}
	}
	return basis
}

// routeOf renders the path as a human "a → b → c" trail for the verdict evidence.
func routeOf(p analyzer.AttackPath) string {
	names := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		names = append(names, n.Name)
	}
	return strings.Join(names, " → ")
}
