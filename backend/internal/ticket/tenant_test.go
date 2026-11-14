package ticket

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A tenant has one spelling in the store: tickets written under the token's spelling, in
// a file or by a caller, are found under the normalized tenant and any other spelling.
func TestTicketsHaveOneTenantWhateverTheSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.json")
	if err := os.WriteFile(path, []byte(`{"tickets":[
		{"id":"t1","tenant":"Acme-Corp","path_id":"ap-1","title":"close it","owner":"secops","status":"open","created_at":"2026-09-01T00:00:00Z"}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, _ := s.List(ctx, "acme_corp"); len(got) != 1 || got[0].Tenant != "acme_corp" {
		t.Fatalf("a ticket written under Acme-Corp, read under acme_corp: %+v", got)
	}
	if _, open, _ := s.OpenForPath(ctx, "ACME-CORP", "ap-1"); !open {
		t.Error("another spelling of the tenant does not find the open ticket")
	}
	if _, err := s.Create(ctx, Ticket{PathID: "ap-2", Tenant: "Acme Corp", Title: "and this", Owner: "secops"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(ctx, "acme_corp"); len(got) != 2 {
		t.Errorf("acme_corp holds %d ticket(s), want 2", len(got))
	}
}
