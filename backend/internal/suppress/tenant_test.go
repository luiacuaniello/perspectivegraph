package suppress

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A tenant has one spelling in the store, whichever its callers use: one writing for a
// token's "Acme-Corp" and one reading for the graph's "acme_corp" meet.
func TestOneTenantWhateverTheSpelling(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Put(ctx, Record{PathID: "ap-1", Tenant: "Acme-Corp", Reason: ReasonAcceptRisk, Owner: "secops"}); err != nil {
		t.Fatal(err)
	}
	if set, err := s.ActiveSet(ctx, "acme_corp"); err != nil || len(set) != 1 {
		t.Fatalf("the analyzer's read under the normalized tenant: %v, %v; want the suppression", set, err)
	}
	if _, ok, _ := s.Get(ctx, "ACME-CORP", "ap-1"); !ok {
		t.Error("a third spelling of the tenant does not find it")
	}
	if err := s.Delete(ctx, "acme corp", "ap-1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(ctx, "Acme-Corp"); len(list) != 0 {
		t.Errorf("deleted under one spelling, still listed under another: %v", list)
	}
}

// A file written before the tenant had one spelling loads under the normalized tenant, and
// where two spellings of one tenant suppressed the same path the later decision stands.
func TestAFileWrittenUnderTheTokensSpellingLoadsNormalized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.json")
	if err := os.WriteFile(path, []byte(`{"records":[
		{"path_id":"ap-1","tenant":"Acme-Corp","reason":"accept-risk","owner":"secops","created_at":"2026-09-01T00:00:00Z"},
		{"path_id":"ap-1","tenant":"acme_corp","reason":"false-positive","owner":"secops","created_at":"2026-09-02T00:00:00Z"},
		{"path_id":"ap-2","tenant":"ACME-CORP","reason":"duplicate","owner":"secops","created_at":"2026-09-03T00:00:00Z"},
		{"path_id":"ap-2","tenant":"Acme-Corp","reason":"accept-risk","owner":"secops","created_at":"2026-09-01T00:00:00Z"}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	list, err := s.List(ctx, "acme_corp")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Reason{}
	for _, r := range list {
		got[r.PathID] = r.Reason
		if r.Tenant != "acme_corp" {
			t.Errorf("%s keeps the tenant %q", r.PathID, r.Tenant)
		}
	}
	if len(got) != 2 || got["ap-1"] != ReasonFalsePositive || got["ap-2"] != ReasonDuplicate {
		t.Errorf("loaded %v; want ap-1 false-positive and ap-2 duplicate, the later decisions", got)
	}
}
