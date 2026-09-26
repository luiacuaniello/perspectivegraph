package impact

import (
	"sync"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Later: the route appeared, or became likelier, through the commit's assets after the
// commit arrived, and no other pull request's change arrived on it at the time. The
// likeliest causes are the rest of a report too large to land in one piece, or a change
// that came from outside any pull request. The route counts - it is real, and it runs
// through the change - but nothing says the change caused it, and the words do not claim
// that it did.
const Later Change = "later"

// Ledger applies the gate's rule to the engine's own pull-request feedback - the commit
// status and the comments it posts from each analysis pass.
//
// Those run long after a report has landed, on a graph that already holds the change, so
// there is no copy to compare with. What stands in for the comparison is the sequence of
// passes itself. Each pass is compared with the one before it: a route between an entry
// and a sensitive asset that is new, or likelier, appeared in between. It belongs to the
// pull-request commits on it that arrived in between - their first pass - as a route they
// opened or worsened. That is the gate's comparison, with the previous pass as the
// estate the change found. A route that was already there when a commit arrived is not
// the commit's, even when it runs through an asset the commit touched.
//
// A route that appears through a commit's assets after it arrived is the change's that
// arrived with it, if one did - a second pull request adding an exposure in front of a
// rescanned image is that second request's doing, not the rescan's. If none did, it
// counts against the commits already on it (Later): conservative, never silent.
//
// A commit that was already in the graph when the ledger started watching - the engine
// restarted, the tenant is new to it - has no "before", and every route through it
// counts, as the gate counts a commit the engine already holds (Recorded).
type Ledger struct {
	mu      sync.Mutex
	tenants map[string]*ledgerTenant
}

type ledgerTenant struct {
	watched bool               // a pass has been observed, so a commit can be seen arriving
	prev    map[string]float64 // route (entry, sensitive asset) -> score, as of the last pass
	commits map[commitRef]*commitState
}

type commitRef struct{ slug, sha string }

type commitState struct {
	// known is false for a commit that was in the graph before the ledger watched.
	known bool
	// routes are the routes that count against the commit, by (entry, sensitive asset).
	routes map[string]attribution
}

type attribution struct {
	change Change
	// before is the route's score before it got likelier; 0 for a route that was not there.
	before float64
}

// NewLedger returns a ledger that has seen nothing yet.
func NewLedger() *Ledger { return &Ledger{tenants: map[string]*ledgerTenant{}} }

// ObservePass records one analysis pass of a tenant's graph: which commits it carries
// and which critical paths it has. The analyzer calls it on every pass it computes, on
// every replica, before any feedback is posted - a change of leader must not start the
// ledger from nothing.
func (l *Ledger) ObservePass(tenant string, snap graph.Snapshot, paths []analyzer.AttackPath) {
	present := map[commitRef]bool{}
	for _, n := range snap.Nodes {
		if ref, ok := stampOf(n.Properties); ok {
			present[ref] = true
		}
	}
	now := make(map[string]float64, len(paths))
	for _, p := range paths {
		if k := pairKey(p); p.Score > now[k] {
			now[k] = p.Score
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	lt := l.tenants[tenant]
	if lt == nil {
		lt = &ledgerTenant{commits: map[commitRef]*commitState{}}
		l.tenants[tenant] = lt
	}
	arrived := map[commitRef]bool{}
	for ref := range present {
		if _, seen := lt.commits[ref]; !seen {
			lt.commits[ref] = &commitState{known: lt.watched, routes: map[string]attribution{}}
			arrived[ref] = true
		}
	}

	if lt.watched {
		for _, p := range paths {
			key := pairKey(p)
			before, existed := lt.prev[key]
			if existed && p.Score <= before+scoreTolerance {
				continue // there before, and no likelier
			}
			if !existed {
				before = 0
			}
			on := commitsOnPath(p)
			newcomers := false
			for _, ref := range on {
				newcomers = newcomers || arrived[ref]
			}
			for _, ref := range on {
				st := lt.commits[ref]
				if st == nil || !st.known {
					continue
				}
				if _, already := st.routes[key]; already {
					continue // the first reason a route counted is the one that stands
				}
				switch {
				case arrived[ref] && !existed:
					st.routes[key] = attribution{change: Introduced}
				case arrived[ref]:
					st.routes[key] = attribution{change: Worsened, before: before}
				case !newcomers:
					st.routes[key] = attribution{change: Later, before: before}
				}
			}
		}
	}

	// A commit that left the graph - a newer push restamped its assets, the pruner aged
	// them out - is forgotten; if it ever comes back, it arrives again.
	for ref := range lt.commits {
		if !present[ref] {
			delete(lt.commits, ref)
		}
	}
	lt.prev = now
	lt.watched = true
}

// Verdict is how a critical path stands with one commit it runs through.
type Verdict struct {
	// Counts reports that the path counts against the commit.
	Counts bool
	// Change says why, when it counts: Introduced or Worsened when the route appeared with
	// the commit, Later when it appeared through the commit's assets afterwards, Recorded
	// when there is no "before" and the per-commit rule decides.
	Change Change
	// PreviousScore is the route's score before it got likelier, when it did.
	PreviousScore float64
}

// Judge reports whether path p counts against the commit (slug, sha) it runs through. A
// nil ledger is the per-commit rule: every route through the commit counts.
func (l *Ledger) Judge(tenant, slug, sha string, p analyzer.AttackPath) Verdict {
	if l == nil {
		return Verdict{Counts: true, Change: Recorded}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var st *commitState
	if lt := l.tenants[tenant]; lt != nil {
		st = lt.commits[commitRef{slug, sha}]
	}
	if st == nil || !st.known {
		return Verdict{Counts: true, Change: Recorded}
	}
	a, ok := st.routes[pairKey(p)]
	if !ok {
		return Verdict{}
	}
	// A route the commit made likelier counts while it stays likelier than it was; one
	// it opened, for as long as it is open.
	if a.before > 0 && p.Score <= a.before+scoreTolerance {
		return Verdict{}
	}
	return Verdict{Counts: true, Change: a.change, PreviousScore: a.before}
}

// Enabled reports whether the ledger compares at all; a nil one applies the per-commit
// rule.
func (l *Ledger) Enabled() bool { return l != nil }

// stampOf reads the pull-request commit a node carries: the repository and the commit,
// both - the pair ontology.StampedWith matches on.
func stampOf(props map[string]any) (commitRef, bool) {
	s, _ := props[ontology.PropRepoSlug].(string)
	c, _ := props[ontology.PropCommitSHA].(string)
	if s == "" || c == "" {
		return commitRef{}, false
	}
	return commitRef{s, c}, true
}

// commitsOnPath lists the distinct commits stamped on a path's nodes.
func commitsOnPath(p analyzer.AttackPath) []commitRef {
	var out []commitRef
	seen := map[commitRef]bool{}
	for _, n := range p.Nodes {
		if ref, ok := stampOf(n.Properties); ok && !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
}
