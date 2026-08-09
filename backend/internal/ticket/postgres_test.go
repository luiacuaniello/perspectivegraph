package ticket

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

func pgStore(t *testing.T) *PGStore {
	t.Helper()
	dsn := os.Getenv("PERSPECTIVE_TEST_MIGRATE_DSN")
	if dsn == "" {
		dsn = "postgres://pg:pg@localhost:5433/pgtest?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("no test database (%v)", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("no test database at %s (%v)", dsn, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := pgmigrate.Apply(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM tickets`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPG(db, "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// THE reason this store had to move. The open-ticket check reads a per-process map in
// the file backend, so two replicas each see no ticket and each opens one: two
// engineers, two tickets, one path, each believing the other's is theirs. Here the check
// is a query, so both see the same answer.
func TestTwoReplicasCannotOpenTwoTicketsForOnePath(t *testing.T) {
	a := pgStore(t)
	b, err := NewPG(a.db, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	first, err := a.Create(ctx, Ticket{Tenant: "acme", PathID: "ap-1", Owner: "team-a", Title: "close it"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Create(ctx, Ticket{Tenant: "acme", PathID: "ap-1", Owner: "team-b", Title: "close it too"})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("two tickets for one path: %s and %s - the work would be done twice or not at all",
			first.ID, second.ID)
	}

	all, err := a.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("%d tickets on the board for one path", len(all))
	}
}

// Closing frees the path for a new ticket - the work came back, so somebody must be able
// to own it again.
func TestClosingFreesThePathForANewTicket(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	tk, err := s.Create(ctx, Ticket{Tenant: "acme", PathID: "ap-2", Owner: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	closed, err := s.Close(ctx, "acme", tk.ID)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closed.Status != StatusClosed || closed.ClosedAt == nil {
		t.Fatalf("close did not stick: %+v", closed)
	}
	if _, ok, _ := s.OpenForPath(ctx, "acme", "ap-2"); ok {
		t.Error("a closed ticket still counts as open")
	}

	again, err := s.Create(ctx, Ticket{Tenant: "acme", PathID: "ap-2", Owner: "team-b"})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == tk.ID {
		t.Error("re-opening returned the closed ticket instead of a new one")
	}
}

// Closing something that is not there must say so rather than silently succeed: the
// caller believes work was completed.
func TestClosingAnUnknownTicketIsAnError(t *testing.T) {
	s := pgStore(t)
	if _, err := s.Close(context.Background(), "acme", "tk-nope"); err == nil {
		t.Fatal("closing an unknown ticket reported success")
	}
}

// Tenants must not see each other's work board.
func TestTicketTenantsAreIsolated(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	for _, tenant := range []string{"acme", "globex"} {
		if _, err := s.Create(ctx, Ticket{Tenant: tenant, PathID: "ap-shared", Owner: "sec"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Tenant != "acme" {
		t.Errorf("acme sees %d rows: %+v", len(list), list)
	}
}

// Validation is shared with the file backend, so the two cannot drift on what counts as
// an accountable ticket.
func TestTicketValidationMatchesTheFileBackend(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	for name, tk := range map[string]Ticket{
		"no path id": {Tenant: "acme", Owner: "sec"},
		"no owner":   {Tenant: "acme", PathID: "ap-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Create(ctx, tk); err == nil {
				t.Error("accepted an unaccountable ticket")
			}
		})
	}
}
