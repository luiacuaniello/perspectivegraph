package age

import (
	"strings"
	"testing"
)

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
		t.Errorf("tag %q occurs in body — would allow breakout", tag)
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
