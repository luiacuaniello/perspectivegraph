package api

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/labrecord"
)

// The Accuracy page reads the lab records through labRuns. Every record built into this
// binary comes back, with its checks and counts, and no record carries an account ID.
func TestLabRunsReturnTheRecordsBuiltIn(t *testing.T) {
	want, err := labrecord.All()
	if err != nil {
		t.Fatal(err)
	}
	data := query(t, seededAPI(t), `{ labRuns { lab title command ranAt engine agreed disagreed unsettled
	    checks { case question referee aws engine verdict } } }`)
	runs, _ := data["labRuns"].([]any)
	if len(runs) != len(want) {
		t.Fatalf("labRuns returned %d runs, the binary carries %d", len(runs), len(want))
	}
	for i, raw := range runs {
		r := raw.(map[string]any)
		checks, _ := r["checks"].([]any)
		if r["lab"] != want[i].Lab || len(checks) != len(want[i].Checks) {
			t.Errorf("run %d: %v with %d checks, want %s with %d", i, r["lab"], len(checks), want[i].Lab, len(want[i].Checks))
		}
		if r["agreed"].(int)+r["disagreed"].(int)+r["unsettled"].(int) != len(checks) {
			t.Errorf("%v: the counts do not add up to its checks", r["lab"])
		}
	}
}
