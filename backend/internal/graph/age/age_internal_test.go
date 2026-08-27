package age

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lib/pq"
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

func TestDollarTagAvoidsCollision(t *testing.T) {
	// A body that contains a fixed tag must not get that tag back.
	body := `RETURN '$pgdeadbeef$ injection'`
	tag, err := dollarTag(body)
	if err != nil {
		t.Fatalf("dollarTag: %v", err)
	}
	if !strings.HasPrefix(tag, "$pg") || !strings.HasSuffix(tag, "$") {
		t.Errorf("unexpected tag shape: %q", tag)
	}
	if strings.Contains(body, tag) {
		t.Errorf("tag %q occurs in body - would allow breakout", tag)
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

func TestCypherQuoteEscapes(t *testing.T) {
	// Single quotes and backslashes must be escaped so a value can't break out
	// of the Cypher string literal.
	got := cypherQuote(`a'b\c`)
	if got != `'a\'b\\c'` {
		t.Errorf("cypherQuote = %q", got)
	}
}

func TestSanitizeIdent(t *testing.T) {
	if got := sanitizeIdent(`Perspective."DROP"`); strings.ContainsAny(got, `."`+" ") {
		t.Errorf("sanitizeIdent left unsafe chars: %q", got)
	}
}
