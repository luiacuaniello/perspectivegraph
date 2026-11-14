package validation

import (
	"context"
	"path/filepath"
	"testing"
)

// A tenant has one spelling in the store. The API wrote verdicts under a token's
// "Acme-Corp" while the analyzer sampled calibration under the graph's "acme_corp", so the
// trend stayed empty for such a tenant; a log written that way now replays normalized.
func TestVerdictsHaveOneTenantWhateverTheSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.log")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Confirmed, with the score the engine gave the path: a calibration sample.
	if _, err := s.Put(ctx, Record{PathID: "ap-1", Outcome: Confirmed, PredictedScore: 0.7, Source: "bas", Tenant: "Acme-Corp"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(ctx, "acme_corp"); len(got) != 1 {
		t.Fatalf("a verdict written under Acme-Corp, read under acme_corp: %d", len(got))
	}
	if c, err := s.Calibration(ctx, "acme_corp"); err != nil || c.Samples != 1 {
		t.Errorf("the analyzer's calibration sample under acme_corp: %+v, %v; want 1 sample", c, err)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := reloaded.List(ctx, "ACME-CORP")
	if len(got) != 1 || got[0].Tenant != "acme_corp" {
		t.Fatalf("after a reload, under another spelling: %+v", got)
	}
	if err := reloaded.Delete(ctx, "Acme-Corp", got[0].ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := reloaded.List(ctx, "acme_corp"); len(left) != 0 {
		t.Errorf("deleted under one spelling, still there under another: %+v", left)
	}
}
