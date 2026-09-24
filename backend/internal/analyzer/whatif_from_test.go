package analyzer

import (
	"context"
	"reflect"
	"testing"
)

// WhatIfFrom exists so a caller proving several cuts runs the uncut simulation once. It
// is only worth having if it changes nothing: given the same simulation WhatIf would have
// run, the result must be identical, field for field.
func TestWhatIfFromMatchesWhatIf(t *testing.T) {
	ctx := context.Background()
	snap := genLayeredGraph(4, 3, 4, 20, 3, 7)
	paths := FindCriticalPaths(snap)
	if len(paths) == 0 {
		t.Fatal("the test graph has no critical path to cut")
	}
	cut := []EdgeCut{{From: paths[0].Steps[0].From, To: paths[0].Steps[0].To}}

	want, err := WhatIf(ctx, snap, cut, 300, 9)
	if err != nil {
		t.Fatal(err)
	}
	before, err := SimulateRisk(ctx, snap, 300, 9)
	if err != nil {
		t.Fatal(err)
	}
	got, err := WhatIfFrom(ctx, snap, before, cut, 300, 9)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WhatIfFrom differs from WhatIf:\n got  %+v\n want %+v", got.AfterRisk, want.AfterRisk)
	}
}

// `seed` is documented as the way to reproduce a simulation, and the whole of one - the
// credible band included - must come out the same for the same seed. The band used to
// differ on every call.
func TestSimulateRiskIsReproducibleFromItsSeed(t *testing.T) {
	snap := genLayeredGraph(4, 3, 4, 20, 3, 7)
	first, err := SimulateRisk(context.Background(), snap, 300, 9)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := SimulateRisk(context.Background(), snap, 300, 9)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again, first) {
			t.Fatalf("run %d differs from the first with the same seed: band [%v, %v] vs [%v, %v]",
				i+2, again.SensitivityLow, again.SensitivityHigh, first.SensitivityLow, first.SensitivityHigh)
		}
	}
}
