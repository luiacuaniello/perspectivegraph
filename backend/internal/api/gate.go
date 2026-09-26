package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The merge gate's endpoint: what does this change add to the estate's attack paths?
//
// POST /gate/impact?source=trivy&slug=owner/name&sha=…[&repo=…&pr=…&account=…], with the
// scanner report as the body - the same report and parameters the ingest webhook takes.
// The report is parsed by the same collector and applied, through the same normalizer,
// to a copy of the tenant's graph held in memory; the answer is the routes the change
// opens or worsens (package impact). Nothing is written. A pipeline that also wants the
// report in the live graph sends it to the ingest webhook as well (the gate's -persist).
//
// It replaces, as the gate's default, the per-commit rule of the prVerdict query - every
// route through an asset stamped with the commit - which blocked a change for routes that
// were there before it. prVerdict stays, unchanged, for the gates already built on it.

// gateMaxBody bounds a report, as the ingest webhook does.
const gateMaxBody = 32 << 20 // 32 MiB

// WithGate enables POST /gate/impact: the collectors that parse reports - the ingest
// webhook's own - and the normalizer a change goes through, configured as the ingest
// path's is (threat intel, secret scrubbing) so it lands in the copy as it would for real.
func (a *API) WithGate(collectors []ingestion.Collector, normalizer func(*graph.Manager) *normalization.Normalizer) *API {
	a.gateCollectors = map[string]ingestion.Collector{}
	for _, c := range collectors {
		a.gateCollectors[c.Source()] = c
	}
	a.gateNormalizer = normalizer
	return a
}

type gateNode struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

type gatePath struct {
	ID            string     `json:"id"`
	Score         float64    `json:"score"`
	Priority      float64    `json:"priority"`
	Change        string     `json:"change"`
	PreviousScore float64    `json:"previousScore,omitempty"`
	Nodes         []gateNode `json:"nodes"`
	// Redacted: the route runs outside the applications the caller may see. It still
	// counts - the answer has to be right - but its assets are not named.
	Redacted bool `json:"redacted,omitempty"`
}

// gateImpact is the answer, in the shape the gate binary reads: prVerdict's fields, with
// what the comparison adds.
type gateImpact struct {
	Attribution   string     `json:"attribution"`
	Analysed      bool       `json:"analysed"`
	CriticalPaths int        `json:"criticalPaths"`
	AnalysedAt    string     `json:"analysedAt"`
	Paths         []gatePath `json:"paths"`
	Preexisting   int        `json:"preexisting"`
	Recorded      bool       `json:"recorded"`
	Reachable     bool       `json:"reachable"`
}

func (a *API) handleGateImpact(w http.ResponseWriter, r *http.Request) {
	if a.gateCollectors == nil {
		writeJSONError(w, http.StatusNotFound, "the gate endpoint is not enabled on this engine")
		return
	}
	// A report of any size, run through a full analysis twice: not something to offer the
	// open internet on a read-only public instance.
	if a.anonymousCaller(r.Context()) {
		metrics.AuthDenied.WithLabelValues("api", "anonymous_gate").Inc()
		writeJSONError(w, http.StatusForbidden, "the gate needs a credential: each call runs a full analysis of the estate")
		return
	}
	q := r.URL.Query()
	source := q.Get("source")
	c, ok := a.gateCollectors[source]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown collector: "+source)
		return
	}
	slug, sha := q.Get("slug"), q.Get("sha")
	if slug == "" || sha == "" {
		writeJSONError(w, http.StatusBadRequest, "slug and sha are required: they identify the change the report belongs to")
		return
	}
	opts := ingestion.Options{Repository: q.Get("repo"), RepoSlug: slug, CommitSHA: sha, Account: q.Get("account")}
	if n, err := strconv.Atoi(q.Get("pr")); err == nil {
		opts.PRNumber = n
	}
	defer r.Body.Close()
	events, err := c.Parse(http.MaxBytesReader(w, r.Body, gateMaxBody), opts)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, ev := range events {
		if err := ontology.ValidateVocabulary(ev); err != nil {
			writeJSONError(w, http.StatusBadRequest, "outside the ontology: "+err.Error())
			return
		}
	}

	// The whole tenant graph, not the caller's applications: a route from an asset the
	// caller may not see to one it may is still a route the change opens, and leaving it
	// out would answer clean. The routes it may not see are counted and not named.
	snap, err := a.rawSnapshot(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not read the graph")
		return
	}
	v, err := a.heavy(r.Context(), "gate|"+source+"|"+slug+"|"+sha, func(ctx context.Context) (any, error) {
		return impact.Evaluate(ctx, impact.Input{Base: snap, Change: events, Slug: slug, SHA: sha, Normalizer: a.gateNormalizer})
	})
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, errComputeBudget), errors.Is(err, context.DeadlineExceeded):
			status = http.StatusServiceUnavailable
		case errors.Is(err, context.Canceled):
			return
		}
		writeJSONError(w, status, fmt.Sprintf("the change could not be evaluated: %v", err))
		return
	}
	res := v.(impact.Result)

	out := gateImpact{
		Attribution: "diff",
		Analysed:    res.Analysed,
		AnalysedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Preexisting: res.Preexisting,
		Recorded:    res.Recorded,
		Reachable:   res.Reachable,
		Paths:       make([]gatePath, 0, len(res.Blocking)),
	}
	apps := allowedApps(r.Context())
	for _, p := range res.Blocking {
		gp := gatePath{ID: p.ID, Score: p.Score, Priority: p.Priority, Change: string(p.Change), PreviousScore: p.PreviousScore, Nodes: []gateNode{}}
		if len(apps) > 0 && !pathMatchesAnyApp(p.AttackPath, apps) {
			gp.ID, gp.Redacted = "", true
		} else {
			for _, n := range p.Nodes {
				gp.Nodes = append(gp.Nodes, gateNode{Name: n.Name, Label: string(n.Label)})
			}
		}
		out.Paths = append(out.Paths, gp)
	}
	out.CriticalPaths = len(out.Paths)
	a.auditView(r.Context(), "gate.impact", map[string]any{"slug": slug, "sha": sha, "paths": out.CriticalPaths})
	writeJSON(w, http.StatusOK, out)
}
