package reqid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(t *testing.T, inbound string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var seen string
	h := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if inbound != "" {
		req.Header.Set(Header, inbound)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, seen
}

func TestEveryRequestGetsAnID(t *testing.T) {
	rec, seen := serve(t, "")
	if seen == "" {
		t.Fatal("the handler saw no request id in its context")
	}
	if got := rec.Header().Get(Header); got != seen {
		t.Errorf("response header %q does not match the context id %q - a caller cannot quote it", got, seen)
	}
}

func TestIDsAreDistinctPerRequest(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		_, id := serve(t, "")
		if seen[id] {
			t.Fatalf("id %q was issued twice - correlation would merge two requests", id)
		}
		seen[id] = true
	}
}

// A gateway or client that already correlates keeps its own thread rather than having a
// second identifier grafted on beside it.
func TestInboundIDIsHonoured(t *testing.T) {
	_, seen := serve(t, "edge-7f3a91")
	if seen != "edge-7f3a91" {
		t.Errorf("inbound id was replaced with %q", seen)
	}
}

// ...but only when it cannot forge structure. This value is echoed into a response
// header, written into the audit log and logged as an attribute, so a caller does not
// get to choose how its own trail reads.
func TestHostileInboundIDsAreReplaced(t *testing.T) {
	hostile := map[string]string{
		"header injection":  "abc\r\nX-Admin: true",
		"newline":           "abc\ndef",
		"log forgery":       `a" level=ERROR msg="AUTH BYPASSED`,
		"space":             "id with spaces",
		"nul":               "abc\x00def",
		"overlong":          strings.Repeat("A", 65),
		"json breakout":     `a","request_id":"b`,
		"unicode direction": "abc\u202edef",
	}
	for name, in := range hostile {
		t.Run(name, func(t *testing.T) {
			rec, seen := serve(t, in)
			if seen == in {
				t.Fatalf("a hostile id was accepted verbatim: %q", in)
			}
			if !strings.HasPrefix(seen, "req-") {
				t.Errorf("expected a generated id, got %q", seen)
			}
			// And nothing hostile reached the response header either.
			hdr := rec.Header().Get(Header)
			if strings.ContainsAny(hdr, "\r\n\x00 \"") {
				t.Errorf("response header carries unsafe characters: %q", hdr)
			}
		})
	}
}

// A context that never went through the middleware has no id, and asking for one must
// not panic - background jobs and tests take that path.
func TestMissingContextIsEmptyNotAPanic(t *testing.T) {
	//lint:ignore SA1012 the point of this test is that a nil context is survivable
	if got := FromContext(nil); got != "" {
		t.Errorf("nil context returned %q", got)
	}
	if got := FromContext(t.Context()); got != "" {
		t.Errorf("a bare context returned %q", got)
	}
}
