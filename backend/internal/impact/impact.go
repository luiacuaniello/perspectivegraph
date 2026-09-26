// Package impact answers the merge gate's question counterfactually: what does this
// change add to the attack paths of the estate as it stands?
//
// The gate used to answer a different question - which attack paths run through an asset
// stamped with the commit - and the two part ways as soon as a change touches something
// that already sits on a route. A pull request that rescans an image already in
// production, or that re-renders every manifest of a deployment, gets its commit stamped
// on assets that were reachable before it existed, and every one of those routes counted
// against it: in the demo lab, nine paths where the change itself opened two. A gate that
// blocks on routes a change did not open is one teams learn to ignore.
//
// So the change is applied to a copy of the estate, in memory - through the same
// normalizer the ingest path runs, so it lands as it would for real - and the critical
// paths of the copy are compared with those of the estate itself. A route between an
// entry and a sensitive asset that did not exist before is one the change opens; one
// that became more likely is one it worsens. Nothing is written: the estate is only read.
package impact

import (
	"context"
	"errors"
	"maps"
	"sort"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Change is why a route counts against the change under test.
type Change string

const (
	// Introduced: no route joined this entry to this sensitive asset before the change.
	Introduced Change = "introduced"
	// Worsened: the route existed, and the change makes it more likely.
	Worsened Change = "worsened"
	// Recorded: the estate already carried this commit before the change was applied -
	// something wrote it into the graph earlier (the gate with persistence on, a pipeline
	// posting the same scan to the ingest webhook) - so a comparison cannot tell the
	// commit's own routes from the ones that were there, and a route through its assets
	// counts as the per-commit gate would count it. Conservative on purpose: it can only
	// block a change the comparison would have passed, never pass one it would block.
	Recorded Change = "recorded"
)

// Path is a critical path the gate counts against the change.
type Path struct {
	analyzer.AttackPath
	Change Change
	// PreviousScore is the route's score before the change, for a worsened route.
	PreviousScore float64
}

// Result is what the change does to the estate's attack paths.
type Result struct {
	// Analysed reports that the change put at least one asset stamped with the commit
	// into the graph. False means the report described nothing the engine could place -
	// the gate answers UNKNOWN, never clean.
	Analysed bool
	// Recorded reports that the estate already carried the commit (see Recorded).
	Recorded bool
	// Reachable reports that at least one of the change's assets can be reached from an
	// attack seed. A change none of whose assets is reachable cannot open a route; when
	// that is a surprise, the usual cause is a scanned image named differently from the
	// workload that runs it.
	Reachable bool
	// Blocking are the routes the gate counts: introduced, worsened and recorded, the
	// highest priority first.
	Blocking []Path
	// Preexisting counts the routes through the change's assets that the change neither
	// opened nor worsened - there before it, and not its doing.
	Preexisting int
	// Waiting counts the edges still waiting for an endpoint once the change is applied:
	// references to assets neither the estate nor the change describes. They cannot be
	// part of a route. Sample is one of them, for the message that explains it.
	Waiting int
	Sample  ontology.Edge
}

// Input is the estate and the change to apply to it.
type Input struct {
	// Base is the estate as it stands. It is copied, never modified.
	Base graph.Snapshot
	// BasePending are the estate's edges still waiting for an endpoint - a workload's
	// link to an image only a scan describes. A snapshot leaves them out; the copy takes
	// them back, so the change's report lands them as the live graph would.
	BasePending []ontology.Edge
	// Change is the change's scanner output, parsed into events and stamped with the
	// commit (slug and sha).
	Change    []ontology.Event
	Slug, SHA string
	// Normalizer builds the normalizer the change goes through. It must be configured
	// as the ingest path's is - threat intel, secret scrubbing - or the change lands
	// differently here than it would for real. nil means normalization.New's defaults.
	Normalizer func(*graph.Manager) *normalization.Normalizer
}

// Evaluate applies the change to a copy of the estate and compares the critical paths.
func Evaluate(ctx context.Context, in Input) (Result, error) {
	store := memory.New()
	nodes := make([]ontology.Node, len(in.Base.Nodes))
	for i, n := range in.Base.Nodes {
		// The snapshot may share its property maps with a live in-memory store; the copy
		// must never write through them.
		n.Properties = maps.Clone(n.Properties)
		nodes[i] = n
	}
	edges := make([]ontology.Edge, 0, len(in.Base.Edges)+len(in.BasePending))
	for _, e := range append(append([]ontology.Edge(nil), in.Base.Edges...), in.BasePending...) {
		e.Properties = maps.Clone(e.Properties)
		edges = append(edges, e)
	}
	if err := store.UpsertBatch(ctx, nodes, edges); err != nil {
		return Result{}, err
	}
	// "Before" is read back from the copy rather than taken from Base, so both sides of
	// the comparison went through the same store: a node listed twice, an edge to a node
	// that is not there, are settled the same way on both.
	before, err := store.Snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	if err != nil {
		return Result{}, err
	}
	norm := normalization.New(mgr)
	if in.Normalizer != nil {
		norm = in.Normalizer(mgr)
	}
	for _, ev := range in.Change {
		// An edge to an asset the estate does not describe waits, as it would in the live
		// graph; it simply cannot be part of a route, which is the honest outcome.
		if err := norm.Handle(ctx, ev); err != nil && !errors.Is(err, graph.ErrEndpointsMissing) {
			return Result{}, err
		}
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	res := compare(before, after, in.Slug, in.SHA)
	waiting, n, err := store.PendingEdges(ctx, 1)
	if err != nil {
		return Result{}, err
	}
	res.Waiting = n
	if len(waiting) > 0 {
		res.Sample = waiting[0]
	}
	return res, nil
}

// compare is the diff itself, on two snapshots: the estate before and after the change.
func compare(before, after graph.Snapshot, slug, sha string) Result {
	var res Result
	for _, n := range before.Nodes {
		if ontology.StampedWith(n.Properties, slug, sha) {
			res.Recorded = true
			break
		}
	}
	mine := map[string]bool{}
	for _, n := range after.Nodes {
		if ontology.StampedWith(n.Properties, slug, sha) {
			mine[n.ID] = true
		}
	}
	res.Analysed = len(mine) > 0
	res.Reachable = anyReachable(after, mine)

	// The best route per (entry, sensitive asset) - one per pair is what the path search
	// returns - before and after.
	was := map[string]analyzer.AttackPath{}
	for _, p := range analyzer.FindCriticalPaths(before) {
		was[pairKey(p)] = p
	}
	now := analyzer.FindCriticalPaths(after)
	analyzer.Prioritize(now)

	for _, p := range now {
		touches := false
		for _, n := range p.Nodes {
			if mine[n.ID] {
				touches = true
				break
			}
		}
		prev, existed := was[pairKey(p)]
		switch {
		case !existed:
			res.Blocking = append(res.Blocking, Path{AttackPath: p, Change: Introduced})
		case p.Score > prev.Score+scoreTolerance:
			res.Blocking = append(res.Blocking, Path{AttackPath: p, Change: Worsened, PreviousScore: prev.Score})
		case touches && res.Recorded:
			res.Blocking = append(res.Blocking, Path{AttackPath: p, Change: Recorded})
		case touches:
			res.Preexisting++
		}
	}
	sort.SliceStable(res.Blocking, func(i, j int) bool {
		a, b := res.Blocking[i], res.Blocking[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})
	return res
}

// scoreTolerance absorbs floating-point noise: a route whose inputs did not change scores
// the same bits, and one the change made likelier moves by far more than this.
const scoreTolerance = 1e-9

// pairKey names the question a route answers - can this entry reach this asset - so a
// route that took a different way to the same place is the same question, better or
// worse answered.
func pairKey(p analyzer.AttackPath) string {
	return p.Source().ID + "\x00" + p.Target().ID
}

// anyReachable reports whether any of the given nodes is reachable from an attack seed,
// whatever the probabilities: the question is whether the change's assets are on the
// attack surface at all.
func anyReachable(snap graph.Snapshot, targets map[string]bool) bool {
	if len(targets) == 0 {
		return false
	}
	adj := map[string][]string{}
	for _, e := range snap.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	seen := map[string]bool{}
	var stack []string
	for _, n := range snap.Nodes {
		if n.IsSeed() && !seen[n.ID] {
			seen[n.ID] = true
			stack = append(stack, n.ID)
		}
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if targets[cur] {
			return true
		}
		for _, next := range adj[cur] {
			if !seen[next] {
				seen[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}
