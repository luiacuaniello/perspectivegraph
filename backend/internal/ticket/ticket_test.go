package ticket

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestCreateValidationAndIdempotency(t *testing.T) {
	ctx := context.Background()
	s, _ := New("", "")

	if _, err := s.Create(ctx, Ticket{Owner: "alice"}); !errors.Is(err, ErrMissingPathID) {
		t.Fatalf("want ErrMissingPathID, got %v", err)
	}
	if _, err := s.Create(ctx, Ticket{PathID: "ap-1"}); !errors.Is(err, ErrMissingOwner) {
		t.Fatalf("want ErrMissingOwner, got %v", err)
	}

	first, err := s.Create(ctx, Ticket{PathID: "ap-1", Owner: "alice", Route: "a → b"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusOpen || first.ID == "" || first.CreatedAt.IsZero() {
		t.Fatalf("unexpected ticket %+v", first)
	}
	// A second create for the same open path returns the same ticket (no fork).
	again, _ := s.Create(ctx, Ticket{PathID: "ap-1", Owner: "bob"})
	if again.ID != first.ID || again.Owner != "alice" {
		t.Fatalf("create should be idempotent per open path; got %+v", again)
	}
	if got, ok := s.OpenForPath("default", "ap-1"); !ok || got.ID != first.ID {
		t.Fatalf("OpenForPath mismatch: %+v ok=%v", got, ok)
	}
}

func TestCloseReopensPath(t *testing.T) {
	ctx := context.Background()
	s, _ := New("", "")
	tk, _ := s.Create(ctx, Ticket{PathID: "ap-1", Owner: "alice"})

	closed, err := s.Close("default", tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != StatusClosed || closed.ClosedAt == nil {
		t.Fatalf("ticket should be closed, got %+v", closed)
	}
	if _, ok := s.OpenForPath("default", "ap-1"); ok {
		t.Error("no open ticket should remain after close")
	}
	// Path can be ticketed again once the prior one is closed.
	reopened, _ := s.Create(ctx, Ticket{PathID: "ap-1", Owner: "carol"})
	if reopened.ID == tk.ID {
		t.Error("a new ticket should be created after the prior closed")
	}
	if _, err := s.Close("default", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("closing a missing ticket should be ErrNotFound, got %v", err)
	}
}

func TestWebhookDispatchAndPersistence(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "nested", "tickets.json")
	s, err := New(path, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Dispatches() || !s.Persistent() {
		t.Fatal("store should be dispatching + persistent")
	}
	tk, _ := s.Create(context.Background(), Ticket{PathID: "ap-9", Owner: "secops", Tenant: "globex"})
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("webhook should have been called once, got %d", hits)
	}

	// Reload from disk: the ticket survives a restart.
	s2, err := New(path, "")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.OpenForPath("globex", "ap-9")
	if !ok || got.ID != tk.ID || got.Owner != "secops" {
		t.Fatalf("ticket should survive reload; got %+v ok=%v", got, ok)
	}
}

func TestNilStoreIsNoop(t *testing.T) {
	var s *Store
	if s.List("default") != nil || s.Persistent() || s.Dispatches() {
		t.Error("nil store should be empty/no-op")
	}
	if _, ok := s.OpenForPath("default", "ap-1"); ok {
		t.Error("nil store OpenForPath should be false")
	}
}
