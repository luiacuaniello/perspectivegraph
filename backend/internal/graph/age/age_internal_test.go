package age

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The four ways `LOAD 'age'` can go, and what each one has to mean. This is the
// difference between a store that runs on a laptop and one that runs on a database
// an organisation can actually buy: no managed PostgreSQL grants superuser, so on
// every one of them the LOAD comes back 42501 while AGE itself works fine, preloaded
// through shared_preload_libraries.
func TestDecideLoadMode(t *testing.T) {
	denied := &pq.Error{Code: "42501", Message: `access to library "age" is not allowed`}
	ok := func() error { return nil }
	broken := func() error { return errors.New(`type "ag_catalog.agtype" does not exist`) }

	t.Run("superuser: LOAD works, so keep loading per transaction", func(t *testing.T) {
		skip, err := decideLoadMode(nil, func() error {
			t.Fatal("probed after a LOAD that succeeded")
			return nil
		})
		if err != nil || skip {
			t.Fatalf("skip=%v err=%v, want skip=false err=nil", skip, err)
		}
	})

	t.Run("managed: LOAD denied but AGE usable, so stop loading", func(t *testing.T) {
		skip, err := decideLoadMode(denied, ok)
		if err != nil {
			t.Fatalf("a preloaded AGE was rejected: %v", err)
		}
		if !skip {
			t.Error("kept LOADing on a role that may not LOAD - every transaction would fail")
		}
	})

	t.Run("misconfigured: LOAD denied and AGE unusable, so say what to fix", func(t *testing.T) {
		_, err := decideLoadMode(denied, broken)
		if err == nil {
			t.Fatal("a server with no usable AGE was accepted")
		}
		if !strings.Contains(err.Error(), "shared_preload_libraries") {
			t.Errorf("got %q, want the remedy named", err)
		}
	})

	t.Run("a non-privilege failure stays fatal", func(t *testing.T) {
		_, err := decideLoadMode(fmt.Errorf("connection reset"), func() error {
			t.Fatal("probed a failure that was never about privileges")
			return nil
		})
		if err == nil {
			t.Fatal("a broken connection was treated as a preloaded AGE")
		}
	})
}

// The 42501 detection reads a driver error, so it is worth pinning that it looks at
// the SQLSTATE and not at the message text, which varies by server version.
func TestIsInsufficientPrivilege(t *testing.T) {
	if !isInsufficientPrivilege(fmt.Errorf("wrapped: %w", &pq.Error{Code: "42501"})) {
		t.Error("42501 not recognised through a wrap")
	}
	if isInsufficientPrivilege(&pq.Error{Code: "42P01", Message: "undefined table"}) {
		t.Error("an unrelated SQLSTATE was read as a privilege error")
	}
	if isInsufficientPrivilege(errors.New(`access to library "age" is not allowed`)) {
		t.Error("matched on message text rather than SQLSTATE")
	}
}

// A body gets the fixed tag, so the same statement has the same text - unless it contains
// that tag, which only a property name can; then it gets one it does not contain.
func TestDollarTagAvoidsCollision(t *testing.T) {
	if tag, err := dollarTag("MATCH (n) WHERE n.id = $id RETURN 1"); err != nil || tag != "$pg$" {
		t.Errorf("an ordinary body got %q, %v; want the fixed $pg$", tag, err)
	}
	for _, body := range []string{"SET n += {`x$pg$y`: $v1}", `RETURN '$pgdeadbeef$ $pg$'`} {
		tag, err := dollarTag(body)
		if err != nil {
			t.Fatalf("dollarTag: %v", err)
		}
		if !strings.HasPrefix(tag, "$pg") || !strings.HasSuffix(tag, "$") {
			t.Errorf("unexpected tag shape: %q", tag)
		}
		if strings.Contains(body, tag) {
			t.Errorf("tag %q occurs in body %q - would allow breakout", tag, body)
		}
	}
}

func TestNewStoreRejectsBadGraphName(t *testing.T) {
	bad := []string{"a'; DROP TABLE x; --", "graph-name", "graph name", "1graph", "", "g$x"}
	for _, name := range bad {
		if _, err := newStore("host=localhost", name); err == nil {
			t.Errorf("graph name %q should be rejected", name)
		}
	}
	// A valid name is accepted (no connection is made until Ping/ensureGraph).
	if _, err := newStore("host=localhost", "perspective_tenant_a"); err != nil {
		t.Errorf("valid graph name rejected: %v", err)
	}
}

// No value reaches the Cypher text. Whatever an id, a name or a property holds - a quote,
// a backslash, a dollar-quote, a Cypher clause - the statement refers to it by name, and
// it travels in the parameter map exactly as it was written.
func TestNoValueIsWrittenIntoTheCypher(t *testing.T) {
	s := &Store{graph: "g"}
	hostile := []string{
		`x' }) DETACH DELETE n //`,
		`name $$ RETURN 1 $$`,
		`$pg0123456789abcdef01$`,
		`back\slash "double" 'single'`,
		"tick ` }) //\nnewline",
	}
	ns, err := s.nodeSQL(ontology.Node{ID: hostile[0], Label: ontology.LabelContainer, Name: hostile[1],
		Properties: map[string]any{"a": hostile[2], "b": hostile[3], "c": hostile[4]}})
	if err != nil {
		t.Fatal(err)
	}
	// An inferred edge, so the statement that keeps a stated one is built too.
	es, err := s.edgeSQL(ontology.Edge{Type: ontology.EdgeConnectsTo, From: hostile[3], To: hostile[4], ExploitProbability: 0.5,
		Properties: map[string]any{"a": hostile[0], ontology.PropResolutionMethod: hostile[1], ontology.PropLastSeen: int64(1_700_000_000)}})
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]cypherStmt{"node update": ns.update, "node create": ns.create, "edge keep": es.keep, "edge upsert": es.upsert} {
		var params map[string]any
		if err := json.Unmarshal([]byte(q.params), &params); err != nil {
			t.Fatalf("%s: parameters are not a JSON map: %v\n%s", name, err, q.params)
		}
		bound := map[string]bool{}
		for _, v := range params {
			if s, ok := v.(string); ok {
				bound[s] = true
			}
		}
		for _, v := range hostile {
			if strings.Contains(q.sql, v) {
				t.Errorf("%s: the value %q is written into the statement:\n%s", name, v, q.sql)
			}
		}
		if !bound[hostile[3]] {
			t.Errorf("%s: %q is not among the bound values %v", name, hostile[3], params)
		}
	}
}

// A value is bound by the rules it was once written into the Cypher by, so what is stored
// keeps its type: an integer stays an integer, a float a float, and a list is its JSON text.
// A number agtype cannot hold fails the write rather than storing something else.
func TestAgtypeValueKeepsTheTypeTheLiteralHad(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{true, "true"},
		{`a"b\c`, `"a\"b\\c"`},
		{1.7e9, "1.7e+09"}, // json.Marshal writes 1700000000, which agtype reads as an integer
		{3.0, "3"},
		{-0.5, "-0.5"},
		{7, "7"},
		{int64(1_700_000_000), "1700000000"},
		{json.Number("12"), "12"},
		{[]string{"a"}, `"[\"a\"]"`},
	} {
		got, err := agtypeValue(c.in)
		if err != nil || got != c.want {
			t.Errorf("agtypeValue(%#v) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []any{math.NaN(), math.Inf(1), json.Number("1} RETURN 1 //")} {
		if got, err := agtypeValue(bad); err == nil {
			t.Errorf("agtypeValue(%#v) = %q, want an error", bad, got)
		}
	}
}

// A property name is the one thing from the data still written into the Cypher - AGE
// takes a map only as a literal - so a backtick in it is doubled, which is how Cypher
// escapes one inside a quoted name.
func TestCypherKeyEscapesABacktick(t *testing.T) {
	if got := cypherKey("a`b c"); got != "`a``b c`" {
		t.Errorf("cypherKey = %s", got)
	}
}

func TestSanitizeIdent(t *testing.T) {
	if got := sanitizeIdent(`Perspective."DROP"`); strings.ContainsAny(got, `."`+" ") {
		t.Errorf("sanitizeIdent left unsafe chars: %q", got)
	}
}

// Every tenant's store shares one pool per database, so the connections a replica holds
// no longer grow with the number of tenants. The pool closes with the last store using
// it, and closing a store twice does not take the pool from under another.
func TestTenantsShareOnePoolPerDatabase(t *testing.T) {
	const dsn = "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable connect_timeout=1"
	a, err := newStore(dsn, "tenant_a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newStore(dsn, "tenant_b")
	if err != nil {
		t.Fatal(err)
	}
	if a.db != b.db {
		t.Fatal("two tenants' stores opened two pools")
	}
	_ = a.Close()
	_ = a.Close() // twice: must not release b's claim
	pools.Lock()
	p := pools.byDSN[dsn]
	pools.Unlock()
	if p == nil || p.refs != 1 {
		t.Fatalf("after closing one of two stores (twice), pool = %+v; want it open with one reference", p)
	}
	_ = b.Close()
	pools.Lock()
	_, open := pools.byDSN[dsn]
	pools.Unlock()
	if open {
		t.Error("the pool outlived its last store")
	}
}
