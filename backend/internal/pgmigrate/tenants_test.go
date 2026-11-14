package pgmigrate

import (
	"context"
	"testing"
	"time"
)

// Rows written under the tenant as tokens spelt it move to its one spelling, so the
// normalized tenant every principal now carries finds them; a path suppressed under two
// spellings keeps the later decision, and a second run moves nothing.
func TestNormalizeTenantsReKeysTheGovernanceTables(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := Apply(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	suppression := `INSERT INTO suppressions (tenant, path_id, reason, owner, created_at) VALUES ($1, $2, $3, 'secops', $4)`
	exec(suppression, "Acme-Corp", "p1", "accept-risk", t0)                   // superseded by the normal one, later
	exec(suppression, "acme_corp", "p1", "false-positive", t0.Add(time.Hour)) // kept
	exec(suppression, "Acme-Corp", "p2", "accept-risk", t0)                   // superseded by ACME-CORP's, later
	exec(suppression, "ACME-CORP", "p2", "duplicate", t0.Add(2*time.Hour))    // kept
	exec(suppression, "Acme-Corp", "p3", "accept-risk", t0)                   // the only one: moved
	exec(suppression, "globex", "p1", "accept-risk", t0)                      // already normal: untouched
	exec(`INSERT INTO tickets (id, tenant, path_id, owner, status, created_at) VALUES ('t1', 'Acme-Corp', 'p1', 'secops', 'open', $1)`, t0)
	exec(`INSERT INTO validations (tenant, id, path_id, outcome, tested_at) VALUES ('Acme-Corp', 'v1', 'p1', 'missed', $1)`, t0)

	moved, err := NormalizeTenants(ctx, db)
	if err != nil {
		t.Fatalf("NormalizeTenants: %v", err)
	}
	// Suppressions: p1 kept in place, p2 and p3 moved; one ticket; one verdict.
	if moved != 4 {
		t.Errorf("moved %d rows, want 4", moved)
	}

	reasons := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT path_id, reason FROM suppressions WHERE tenant = 'acme_corp'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p, r string
		if err := rows.Scan(&p, &r); err != nil {
			t.Fatal(err)
		}
		reasons[p] = r
	}
	_ = rows.Close()
	want := map[string]string{"p1": "false-positive", "p2": "duplicate", "p3": "accept-risk"}
	for p, r := range want {
		if reasons[p] != r {
			t.Errorf("acme_corp %s: reason %q, want %q (the later decision)", p, reasons[p], r)
		}
	}
	if len(reasons) != len(want) {
		t.Errorf("acme_corp holds %v, want %v", reasons, want)
	}
	var left int
	if err := db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM suppressions WHERE tenant NOT IN ('acme_corp', 'globex'))
		     + (SELECT count(*) FROM tickets WHERE tenant <> 'acme_corp')
		     + (SELECT count(*) FROM validations WHERE tenant <> 'acme_corp')`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d row(s) left under a spelling that is not normal", left)
	}
	if again, err := NormalizeTenants(ctx, db); err != nil || again != 0 {
		t.Errorf("a second run: moved %d, %v; want nothing", again, err)
	}
}
