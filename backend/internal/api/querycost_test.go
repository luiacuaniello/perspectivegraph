package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fragmentBomb builds a document with n fragments, each spreading the next TWICE. There
// is no cycle anywhere, so a cycle guard does not help: a naive expander descends 2^n
// times. Thirty fragments fit in about 1.2 KB.
func fragmentBomb(n int) string {
	var b strings.Builder
	b.WriteString("query { ...F0 }\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "fragment F%d on Query { ...F%d ...F%d }\n", i, i+1, i+1)
	}
	fmt.Fprintf(&b, "fragment F%d on Query { attackPaths { id } }\n", n)
	return b.String()
}

// The guard that exists to prevent a denial of service must not be one. Before fragment
// costs were memoised this document took over ten seconds to MEASURE - 4.4 s at
// twenty-five fragments, 125 ms at twenty - all of it before a single field resolved,
// from a request small enough to send thousands of times a second.
func TestFragmentBombIsMeasuredInLinearTime(t *testing.T) {
	for _, n := range []int{30, 60, 200} {
		q := fragmentBomb(n)
		done := make(chan cost, 1)
		start := time.Now()
		go func() { c, _ := queryCost(q); done <- c }()

		select {
		case c := <-done:
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("n=%d (%d bytes): measuring took %v - the expansion is not linear", n, len(q), elapsed)
			}
			// It must also be REJECTED, not merely measured quickly.
			if c.selections <= maxQuerySelections {
				t.Errorf("n=%d: counted only %d selections, so the bomb would execute", n, c.selections)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("n=%d (%d bytes): queryCost did not terminate - this is the DoS", n, len(q))
		}
	}
}

// Aliases are the other half of the budget, and the half depth limits cannot see: the
// same expensive field asked for thousands of times is shallow and perfectly legal.
func TestAliasAmplificationIsRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString("query {")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, " a%d: attackPaths { id }", i)
	}
	b.WriteString(" }")

	c, err := queryCost(b.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.depth > maxQueryDepth {
		t.Fatalf("depth = %d: this must be caught by the COMPLEXITY limit, not the depth one", c.depth)
	}
	if c.selections <= maxQuerySelections {
		t.Fatalf("3000 aliased resolutions counted as %d selections - under the %d budget", c.selections, maxQuerySelections)
	}
}

// A self-referential fragment is invalid GraphQL, but a client can still send one.
func TestCyclicFragmentIsPoisonedNotFollowed(t *testing.T) {
	done := make(chan cost, 1)
	go func() {
		c, _ := queryCost(`query { ...a } fragment a on Query { ...b } fragment b on Query { ...a }`)
		done <- c
	}()
	select {
	case c := <-done:
		if c.depth <= maxQueryDepth && c.selections <= maxQuerySelections {
			t.Fatalf("a cyclic document was accepted: %+v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cyclic fragment made queryCost hang")
	}
}

// The budget must be invisible to real use, or it will be raised until it is useless.
func TestRealisticQueriesAreWellUnderBudget(t *testing.T) {
	queries := []string{
		`{ posture { criticalPaths riskScore } }`,
		`{ attackPaths(limit: 50) { id score priority nodes { id label name } steps { from to probability edge_type } } }`,
		`query Board { attackPaths { id score } posture { criticalPaths } ingestCoverage { source events stale } }`,
	}
	for _, q := range queries {
		c, err := queryCost(q)
		if err != nil {
			t.Fatalf("parse %q: %v", q, err)
		}
		if c.selections > maxQuerySelections/4 {
			t.Errorf("a realistic query costs %d selections, uncomfortably close to the %d budget: %s",
				c.selections, maxQuerySelections, q)
		}
		if c.depth > maxQueryDepth {
			t.Errorf("a realistic query is %d deep, over the %d limit: %s", c.depth, maxQueryDepth, q)
		}
	}
}

// A request executes ONE operation, so a document holding several must be charged for
// the dearest one rather than their total - otherwise a GraphiQL user with a few saved
// queries in the editor gets a complexity rejection for a query the server never runs.
func TestMultipleOperationsAreChargedForTheDearestOne(t *testing.T) {
	one, err := queryCost(`query A { attackPaths { id score } }`)
	if err != nil {
		t.Fatal(err)
	}
	many, err := queryCost(`
		query A { attackPaths { id score } }
		query B { attackPaths { id score } }
		query C { attackPaths { id score } }`)
	if err != nil {
		t.Fatal(err)
	}
	if many.selections != one.selections {
		t.Errorf("three copies of one operation cost %d selections, want %d - only one of them executes",
			many.selections, one.selections)
	}
}

// ...but the dearest one still has to be the one that counts.
func TestTheDearestOperationSetsTheCost(t *testing.T) {
	c, err := queryCost(`
		query Cheap { posture { criticalPaths } }
		query Dear { attackPaths { id score nodes { id name label } steps { from to probability } } }`)
	if err != nil {
		t.Fatal(err)
	}
	dear, _ := queryCost(`query Dear { attackPaths { id score nodes { id name label } steps { from to probability } } }`)
	if c.selections != dear.selections {
		t.Errorf("the document costs %d, but its most expensive operation costs %d", c.selections, dear.selections)
	}
}

// Aliases each count once: two names for the same field are two resolutions, which is
// the whole reason the count exists.
func TestEachAliasCountsSeparately(t *testing.T) {
	one, _ := queryCost(`{ posture { criticalPaths } }`)
	two, _ := queryCost(`{ a: posture { criticalPaths } b: posture { criticalPaths } }`)
	if two.selections != 2*one.selections {
		t.Errorf("aliasing a field twice cost %d selections, want %d", two.selections, 2*one.selections)
	}
	if two.depth != one.depth {
		t.Errorf("aliasing changed the depth from %d to %d", one.depth, two.depth)
	}
}

// End to end through the middleware: the client gets a 400 naming the reason, not a
// timeout and not a stalled worker.
func TestGuardRejectsOverBudgetQueriesWithA400(t *testing.T) {
	var aliases strings.Builder
	aliases.WriteString("query {")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&aliases, " a%d: attackPaths { id }", i)
	}
	aliases.WriteString(" }")

	cases := []struct{ name, query, wantMsg string }{
		{"fragment bomb", fragmentBomb(30), "complexity"},
		{"alias amplification", aliases.String(), "complexity"},
		{"too deep", strings.Repeat("{ a ", 40) + strings.Repeat("}", 40), "depth"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reached := false
			h := withQueryGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

			body := `{"query":` + quoteJSON(c.query) + `}`
			req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
			rec := httptest.NewRecorder()

			done := make(chan struct{})
			go func() { h.ServeHTTP(rec, req); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the guard never returned")
			}

			if reached {
				t.Error("an over-budget query reached the executor")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), c.wantMsg) {
				t.Errorf("the rejection does not say %q: %s", c.wantMsg, rec.Body.String())
			}
		})
	}
}

// quoteJSON is enough for the fixed, ASCII test documents above.
func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
