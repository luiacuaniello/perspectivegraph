package ingestion

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// withSnapshot is a collector's event that declares itself complete for scope.
func withSnapshot(source, scope string) []ontology.Event {
	evs := oneEvent(source)
	evs[0].Snapshot = &ontology.Snapshot{Scope: scope}
	return evs
}

// How an ingest becomes a complete snapshot - the declaration that makes the engine
// retract what it omits - and every way it must not.
func TestTheSnapshotDeclaration(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		produces    []ontology.Event
		wantScope   string // "" = partial
		wantStatus  int
	}{
		{"the collector vouches for its scope", "", withSnapshot("trivy", "image:app:1.0"), "image:app:1.0", http.StatusAccepted},
		{"a collector that does not is partial", "", oneEvent("k8s"), "", http.StatusAccepted},
		{"the sender names the scope", "?snapshot=cluster:prod", oneEvent("k8s"), "cluster:prod", http.StatusAccepted},
		{"the sender declares a filtered scan partial", "?snapshot=none", withSnapshot("trivy", "image:app:1.0"), "", http.StatusAccepted},
		{"a pull request's scan is never complete", "?slug=acme/app&sha=abc", withSnapshot("trivy", "image:app:1.0"), "", http.StatusAccepted},
		{"asking for it on a pull request is refused", "?slug=acme/app&sha=abc&snapshot=cluster:prod", oneEvent("k8s"), "", http.StatusBadRequest},
		{"a scope with a space is refused", "?snapshot=my%20cluster", oneEvent("k8s"), "", http.StatusBadRequest},
		{"an overlong scope is refused", "?snapshot=" + strings.Repeat("x", ontology.MaxScopeLen+1), oneEvent("k8s"), "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := &batchPublisher{}
			c := &fakeCollector{source: tc.produces[0].Source, produces: tc.produces}
			before := time.Now().UTC()
			rec := do(NewServer(pub, c).Handler(),
				httptest.NewRequest(http.MethodPost, "/ingest/"+c.source+tc.query, strings.NewReader("{}")))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d (%s), want %d", rec.Code, rec.Body, tc.wantStatus)
			}
			if tc.wantStatus != http.StatusAccepted {
				if len(pub.got) != 0 {
					t.Errorf("a refused ingest published %d event(s)", len(pub.got))
				}
				return
			}
			got := pub.got[0].Snapshot
			switch {
			case tc.wantScope == "" && got != nil:
				t.Fatalf("snapshot %+v, want a partial ingest", got)
			case tc.wantScope != "" && (got == nil || got.Scope != tc.wantScope):
				t.Fatalf("snapshot %+v, want scope %q", got, tc.wantScope)
			case got != nil && got.Taken.Before(before):
				t.Errorf("taken %v: the engine stamps the time it received the snapshot", got.Taken)
			}
		})
	}
}

// A pre-normalized event cannot declare itself complete from its body: the one way to
// ask is the query parameter, where an operator writes it on purpose - not a field an
// event copied from somewhere else carries in unnoticed.
func TestAnEventsBodyCannotDeclareASnapshot(t *testing.T) {
	body := `{"source":"k8s","kind":"asset","nodes":[{"id":"n1","label":"Container","name":"x"}],
		"snapshot":{"scope":"cluster:prod","taken":"2020-01-01T00:00:00Z"}}`
	pub := &batchPublisher{}
	rec := do(NewServer(pub).Handler(), httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(body)))
	if rec.Code != http.StatusAccepted || pub.got[0].Snapshot != nil {
		t.Fatalf("status %d, snapshot %+v: the body's declaration was honoured", rec.Code, pub.got[0].Snapshot)
	}
	pub = &batchPublisher{}
	rec = do(NewServer(pub).Handler(), httptest.NewRequest(http.MethodPost, "/ingest/events?snapshot=cluster:prod", strings.NewReader(body)))
	if sn := pub.got[0].Snapshot; rec.Code != http.StatusAccepted || sn == nil || sn.Scope != "cluster:prod" || sn.Taken.Year() == 2020 {
		t.Fatalf("status %d, snapshot %+v: want the parameter's scope, taken now", rec.Code, sn)
	}
}

// An event whose nodes carry a pull request's commit never retracts, whoever declares it.
func TestAnEventCarryingAPullRequestIsNeverComplete(t *testing.T) {
	body := `{"source":"k8s","kind":"asset","nodes":[{"id":"n1","label":"Container","name":"x",
		"properties":{"repo_slug":"acme/app","commit_sha":"abc"}}]}`
	pub := &batchPublisher{}
	rec := do(NewServer(pub).Handler(), httptest.NewRequest(http.MethodPost, "/ingest/events?snapshot=cluster:prod", strings.NewReader(body)))
	if rec.Code != http.StatusAccepted || pub.got[0].Snapshot != nil {
		t.Fatalf("status %d, snapshot %+v", rec.Code, pub.got[0].Snapshot)
	}
}
