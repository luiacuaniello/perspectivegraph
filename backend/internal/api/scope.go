package api

import (
	"context"
	"log/slog"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/broker"
	"github.com/luiacuaniello/perspectivegraph/internal/coverage"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// What a caller may read is decided here, once: which spelling of the caller's tenant each
// store is read under, and what a caller limited to some applications may see. The GraphQL
// resolvers read through view and take a tenant or an application list from nowhere else -
// TestResolversReadThroughTheView fails on a schema file that asks the request context for
// one, or reads a store directly.
//
// One tenant has two spellings because the stores were built apart. The governance stores
// (suppressions, tickets, validations), the analyzer, the coverage ledger and the search
// index are read under the tenant as its token spells it - the index normalizes it itself.
// The history is read under the normalized form the analyzer writes it with. The October
// fixes to search and history were resolvers that read a store under the other spelling,
// and found nothing.

// scoped is who is asking, in the forms the stores need.
type scoped struct {
	// tenant is the caller's tenant as its token spells it.
	tenant string
	// graphTenant is the same tenant normalized (graph.NormalizeTenant): "Acme-Corp" is
	// "acme_corp" here.
	graphTenant string
	// apps is the caller's application allowlist; empty is unrestricted.
	apps []string
}

func scopeOf(ctx context.Context) scoped {
	p := auth.PrincipalFromContext(ctx)
	return scoped{tenant: p.Tenant, graphTenant: graph.NormalizeTenant(p.Tenant), apps: p.Apps}
}

// restricted reports whether the caller is limited to some applications.
func (s scoped) restricted() bool { return len(s.apps) > 0 }

// tenantOf is the caller's tenant as its token spells it.
func tenantOf(ctx context.Context) string { return scopeOf(ctx).tenant }

// allowedApps is the caller's application allowlist (empty = unrestricted).
func allowedApps(ctx context.Context) []string { return scopeOf(ctx).apps }

// view is what one request may read: each store under the key it is written with, and the
// graph and the paths limited to the caller's applications.
type view struct {
	a   *API
	ctx context.Context
	scoped
}

func (a *API) view(ctx context.Context) view {
	return view{a: a, ctx: ctx, scoped: scopeOf(ctx)}
}

// ── the graph and the paths, limited to the caller's applications ──

// snapshot returns the per-request graph snapshot, restricted to the caller's allowed
// applications when the principal is app-scoped.
func (v view) snapshot() (graph.Snapshot, error) {
	snap, err := v.a.rawSnapshot(v.ctx)
	if err != nil {
		return snap, err
	}
	if v.restricted() {
		nodes, edges := filterByApps(snap, v.apps)
		return graph.Snapshot{Nodes: nodes, Edges: edges}, nil
	}
	return snap, nil
}

// latest is the analyzer's latest attack paths, restricted to the ones touching the
// caller's allowed applications.
func (v view) latest() []analyzer.AttackPath {
	paths := v.a.analyzer.Latest(v.tenant)
	if !v.restricted() {
		return paths
	}
	out := make([]analyzer.AttackPath, 0, len(paths))
	for _, p := range paths {
		if pathMatchesAnyApp(p, v.apps) {
			out = append(out, p)
		}
	}
	return out
}

// shownPaths is latest re-banded by the red-team and BAS verdicts recorded on the paths
// (analyzer.ApplyVerdicts): the order and bands the dashboard shows. What GRADES the
// ranking - the Priority captured with a verdict - reads latest instead, which carries
// none, so a verdict can never be graded against a ranking it already moved.
func (v view) shownPaths() []analyzer.AttackPath {
	paths := v.latest()
	if v.a.validation == nil || len(paths) == 0 {
		return paths
	}
	records, err := v.a.validation.List(v.ctx, v.tenant)
	if err != nil {
		slog.Warn("attack paths shown without their test verdicts", "err", err)
		return paths
	}
	latest := make(map[string]analyzer.Verdict, len(records))
	for _, r := range records { // newest first: the first verdict per path is its current one
		if r.PathID == "" || r.Outcome == validation.Missed {
			continue
		}
		if _, seen := latest[r.PathID]; !seen {
			latest[r.PathID] = analyzer.Verdict{Outcome: string(r.Outcome), Source: r.Source}
		}
	}
	return analyzer.ApplyVerdicts(paths, func(id string) (analyzer.Verdict, bool) {
		v, ok := latest[id]
		return v, ok
	})
}

// pathIDs is the set of attack-path ids the caller may act on, or nil when the caller is
// unrestricted.
//
// The governance stores - suppressions, tickets, validations - are keyed by path id and
// scoped by TENANT alone, so before this an app-scoped admin could suppress a path
// belonging to another team's application: hiding a real finding from the people
// responsible for it, silently. That is the same boundary latest enforces on reads,
// applied to the records that reference those paths.
//
// nil for an unrestricted caller is deliberate: every call site skips the work entirely,
// so the single-team deployment - which is most of them - pays nothing and behaves
// exactly as before.
func (v view) pathIDs() map[string]bool {
	if !v.restricted() {
		return nil
	}
	paths := v.latest()
	ids := make(map[string]bool, len(paths))
	for _, p := range paths {
		ids[p.ID] = true
	}
	return ids
}

// mayActOnPath reports whether the caller may read or write a governance record for
// pathID. An app-scoped caller may only reach paths currently surfaced within its
// applications: a path that is no longer live cannot be attributed to an application,
// so it is refused rather than guessed at.
func (v view) mayActOnPath(pathID string) bool {
	ids := v.pathIDs()
	return ids == nil || ids[pathID]
}

// violations is the policy invariants currently violated, those touching the caller's
// applications when it is limited to some.
func (v view) violations() []policy.Violation {
	all := v.a.analyzer.Violations(v.tenant)
	if !v.restricted() {
		return all
	}
	out := all[:0:0]
	for _, viol := range all {
		for _, n := range viol.Nodes {
			if nodeMatchesAnyApp(n, v.apps) {
				out = append(out, viol)
				break
			}
		}
	}
	return out
}

// latestRisk is the analyzer's cached risk simulation. Its probabilities are aggregates of
// the tenant and name nothing, so every caller gets them as they are. Its crown jewels are
// named, so a caller limited to some applications gets the ones its part of the graph
// holds - the same ones the query simulates when it is given arguments of its own. The
// cached simulation used to list every jewel of the tenant to any caller.
func (v view) latestRisk() (analyzer.RiskSimulation, error) {
	risk := v.a.analyzer.LatestRisk(v.tenant)
	if !v.restricted() || len(risk.CrownJewels) == 0 {
		return risk, nil
	}
	snap, err := v.snapshot()
	if err != nil {
		return analyzer.RiskSimulation{}, err
	}
	visible := make(map[string]bool, len(snap.Nodes))
	for _, n := range snap.Nodes {
		visible[n.ID] = true
	}
	jewels := make([]analyzer.CrownJewelRisk, 0, len(risk.CrownJewels))
	for _, j := range risk.CrownJewels {
		if visible[j.ID] {
			jewels = append(jewels, j)
		}
	}
	risk.CrownJewels = jewels // a new slice: the cached simulation is shared
	return risk, nil
}

// find runs a full-text search, keeping for a caller limited to some applications only
// the hits for assets in its part of the graph, so search cannot reveal other
// applications' assets.
func (v view) find(query string, size int) ([]search.Hit, error) {
	hits, err := v.a.search.Search(v.ctx, v.tenant, query, size)
	if err != nil {
		return nil, err
	}
	if !v.restricted() {
		return hits, nil
	}
	snap, err := v.snapshot()
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(snap.Nodes))
	for _, n := range snap.Nodes {
		allowed[n.ID] = true
	}
	out := hits[:0]
	for _, h := range hits {
		if allowed[h.ID] {
			out = append(out, h)
		}
	}
	return out, nil
}

// searchEnabled reports whether a full-text index is configured.
func (v view) searchEnabled() bool { return v.a.search.Enabled() }

// ── governance records, under the tenant as its token spells it ──

func (v view) suppression(pathID string) (suppress.Record, bool, error) {
	return v.a.suppress.Get(v.ctx, v.tenant, pathID)
}

func (v view) suppressions() (map[string]suppress.Record, error) {
	return v.a.suppress.ActiveSet(v.ctx, v.tenant)
}

func (v view) openTicket(pathID string) (ticket.Ticket, bool, error) {
	return v.a.ticket.OpenForPath(v.ctx, v.tenant, pathID)
}

func (v view) verdict(pathID string) (validation.Record, bool, error) {
	return v.a.validation.Get(v.ctx, v.tenant, pathID)
}

// validationMetrics and calibration measure the engine across the tenant. They name
// nothing, so they are not limited to the caller's applications - a decision held by
// TestValidationsBoardIsScopedButItsAggregatesAreNot.
func (v view) validationMetrics() (validation.Metrics, error) {
	return v.a.validation.Metrics(v.ctx, v.tenant)
}

func (v view) calibration() (validation.Calibration, error) {
	return v.a.validation.Calibration(v.ctx, v.tenant)
}

// ── the analyzer's and the feeds' aggregates of the tenant, which name nothing ──

func (v view) status() analyzer.Status { return v.a.analyzer.Status(v.tenant) }

// violationCount is how many policy invariants the tenant violates: a count, which names
// nothing, so it is the tenant's whatever the caller's applications.
func (v view) violationCount() int { return len(v.a.analyzer.Violations(v.tenant)) }

func (v view) feeds() []coverage.Source { return v.a.coverage.Snapshot(v.tenant) }

// batch is the progress of an ingest batch the caller's tenant sent. Another tenant's, like
// an unknown id, is not there: the caller learns nothing about it.
func (v view) batch(id string) (broker.BatchStatus, bool, error) {
	if v.a.batches == nil {
		return broker.BatchStatus{}, false, nil
	}
	st, err := v.a.batches.BatchStatus(v.ctx, id)
	if err != nil {
		return broker.BatchStatus{}, false, err
	}
	if st.Messages == 0 || graph.NormalizeTenant(st.Tenant) != v.graphTenant {
		return broker.BatchStatus{}, false, nil
	}
	return st, true, nil
}

// ── the history, under the normalized tenant ──

func (v view) pathHistory(pathID string) (history.PathRecord, bool) {
	return v.a.history.Get(v.graphTenant, pathID)
}

func (v view) postureHistory(points int) historyView {
	return historyView{
		Trend:      v.a.history.Trend(v.graphTenant, points),
		Stats:      v.a.history.Stats(v.graphTenant),
		Persistent: v.a.history.Persistent(),
	}
}

func (v view) calibrationTrend(limit int) []history.CalibrationSample {
	return v.a.history.CalibrationTrend(v.graphTenant, limit)
}

// The API's own reads, for the REST handlers: the same as the resolvers'.

func (a *API) snapshot(ctx context.Context) (graph.Snapshot, error) { return a.view(ctx).snapshot() }

func (a *API) scopedLatest(ctx context.Context) []analyzer.AttackPath { return a.view(ctx).latest() }

func (a *API) scopedPathIDs(ctx context.Context) map[string]bool { return a.view(ctx).pathIDs() }

func (a *API) mayActOnPath(ctx context.Context, pathID string) bool {
	return a.view(ctx).mayActOnPath(pathID)
}
