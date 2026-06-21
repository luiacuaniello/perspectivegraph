// Package api is the Backend-For-Frontend. It exposes a GraphQL schema so the
// dashboard can ask for exactly the slice of the graph it needs (attack paths,
// posture summary, policy violations, full-text search, or the raw node/edge
// view for Cytoscape).
package api

import (
	"github.com/aegisgraph/aegisgraph/internal/analyzer"
	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/internal/policy"
	"github.com/aegisgraph/aegisgraph/internal/remediation"
	"github.com/aegisgraph/aegisgraph/internal/search"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
	"github.com/graphql-go/graphql"
)

// API wires the data sources the resolvers read from.
type API struct {
	store    graph.Store
	analyzer *analyzer.Service
	search   search.Indexer
}

func New(store graph.Store, svc *analyzer.Service, idx search.Indexer) *API {
	if idx == nil {
		idx = search.Noop{}
	}
	return &API{store: store, analyzer: svc, search: idx}
}

func (a *API) Schema() (graphql.Schema, error) {
	nodeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Node",
		Fields: graphql.Fields{
			"id":              &graphql.Field{Type: graphql.NewNonNull(graphql.String), Resolve: nodeField(func(n ontology.Node) any { return n.ID })},
			"label":           &graphql.Field{Type: graphql.String, Resolve: nodeField(func(n ontology.Node) any { return string(n.Label) })},
			"name":            &graphql.Field{Type: graphql.String, Resolve: nodeField(func(n ontology.Node) any { return n.Name })},
			"internetExposed": &graphql.Field{Type: graphql.Boolean, Resolve: nodeField(func(n ontology.Node) any { return n.Bool(ontology.PropInternetExposed) })},
			"crownJewel":      &graphql.Field{Type: graphql.Boolean, Resolve: nodeField(func(n ontology.Node) any { return n.Bool(ontology.PropCrownJewel) })},
			"runtimeAlert":    &graphql.Field{Type: graphql.Boolean, Resolve: nodeField(func(n ontology.Node) any { return n.Bool(ontology.PropRuntimeAlert) })},
			"severity":        &graphql.Field{Type: graphql.String, Resolve: nodeField(func(n ontology.Node) any { return n.Properties[ontology.PropSeverity] })},
			"cvss":            &graphql.Field{Type: graphql.Float, Resolve: nodeField(func(n ontology.Node) any { return n.Properties[ontology.PropCVSS] })},
		},
	})

	edgeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Edge",
		Fields: graphql.Fields{
			"type":        &graphql.Field{Type: graphql.String, Resolve: edgeField(func(e ontology.Edge) any { return string(e.Type) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: edgeField(func(e ontology.Edge) any { return e.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: edgeField(func(e ontology.Edge) any { return e.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: edgeField(func(e ontology.Edge) any { return e.ExploitProbability })},
		},
	})

	stepType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPathStep",
		Fields: graphql.Fields{
			"edgeType":    &graphql.Field{Type: graphql.String, Resolve: stepField(func(s analyzer.Step) any { return string(s.EdgeType) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: stepField(func(s analyzer.Step) any { return s.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: stepField(func(s analyzer.Step) any { return s.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: stepField(func(s analyzer.Step) any { return s.Probability })},
		},
	})

	suggestionType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Remediation",
		Fields: graphql.Fields{
			"title":     &graphql.Field{Type: graphql.String, Resolve: suggestionField(func(s remediation.Suggestion) any { return s.Title })},
			"kind":      &graphql.Field{Type: graphql.String, Resolve: suggestionField(func(s remediation.Suggestion) any { return s.Kind })},
			"filename":  &graphql.Field{Type: graphql.String, Resolve: suggestionField(func(s remediation.Suggestion) any { return s.Filename })},
			"content":   &graphql.Field{Type: graphql.String, Resolve: suggestionField(func(s remediation.Suggestion) any { return s.Content })},
			"rationale": &graphql.Field{Type: graphql.String, Resolve: suggestionField(func(s remediation.Suggestion) any { return s.Rationale })},
		},
	})

	pathType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPath",
		Fields: graphql.Fields{
			"id":               &graphql.Field{Type: graphql.String, Resolve: pathField(func(p analyzer.AttackPath) any { return p.ID })},
			"score":            &graphql.Field{Type: graphql.Float, Resolve: pathField(func(p analyzer.AttackPath) any { return p.Score })},
			"runtimeConfirmed": &graphql.Field{Type: graphql.Boolean, Resolve: pathField(func(p analyzer.AttackPath) any { return p.RuntimeConfirmed })},
			"nodes":            &graphql.Field{Type: graphql.NewList(nodeType), Resolve: pathField(func(p analyzer.AttackPath) any { return p.Nodes })},
			"steps":            &graphql.Field{Type: graphql.NewList(stepType), Resolve: pathField(func(p analyzer.AttackPath) any { return p.Steps })},
			"remediations": &graphql.Field{
				Type:        graphql.NewList(suggestionType),
				Description: "Generated artifacts (K8s NetworkPolicy / Terraform) that cut an edge of this path.",
				Resolve:     pathField(func(p analyzer.AttackPath) any { return remediation.Generate(p) }),
			},
		},
	})

	violationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "PolicyViolation",
		Fields: graphql.Fields{
			"invariantId": &graphql.Field{Type: graphql.String, Resolve: violationField(func(v policy.Violation) any { return v.InvariantID })},
			"description": &graphql.Field{Type: graphql.String, Resolve: violationField(func(v policy.Violation) any { return v.Description })},
			"severity":    &graphql.Field{Type: graphql.String, Resolve: violationField(func(v policy.Violation) any { return v.Severity })},
			"nodes":       &graphql.Field{Type: graphql.NewList(nodeType), Resolve: violationField(func(v policy.Violation) any { return v.Nodes })},
		},
	})

	hitType := graphql.NewObject(graphql.ObjectConfig{
		Name: "SearchHit",
		Fields: graphql.Fields{
			"id":    &graphql.Field{Type: graphql.String, Resolve: hitField(func(h search.Hit) any { return h.ID })},
			"label": &graphql.Field{Type: graphql.String, Resolve: hitField(func(h search.Hit) any { return h.Label })},
			"name":  &graphql.Field{Type: graphql.String, Resolve: hitField(func(h search.Hit) any { return h.Name })},
			"score": &graphql.Field{Type: graphql.Float, Resolve: hitField(func(h search.Hit) any { return h.Score })},
		},
	})

	graphViewType := graphql.NewObject(graphql.ObjectConfig{
		Name: "GraphView",
		Fields: graphql.Fields{
			"nodes": &graphql.Field{Type: graphql.NewList(nodeType)},
			"edges": &graphql.Field{Type: graphql.NewList(edgeType)},
		},
	})

	postureType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Posture",
		Fields: graphql.Fields{
			"criticalPaths":    &graphql.Field{Type: graphql.Int},
			"runtimeConfirmed": &graphql.Field{Type: graphql.Int},
			"policyViolations": &graphql.Field{Type: graphql.Int},
			"nodes":            &graphql.Field{Type: graphql.Int},
			"edges":            &graphql.Field{Type: graphql.Int},
		},
	})

	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"attackPaths": &graphql.Field{
				Type:        graphql.NewList(pathType),
				Description: "Critical attack paths from the latest analysis pass, ranked (runtime-confirmed first, then score).",
				Resolve: func(graphql.ResolveParams) (any, error) {
					return a.analyzer.Latest(), nil
				},
			},
			"invariantViolations": &graphql.Field{
				Type:        graphql.NewList(violationType),
				Description: "Architectural policy invariants currently violated.",
				Resolve: func(graphql.ResolveParams) (any, error) {
					return a.analyzer.Violations(), nil
				},
			},
			"search": &graphql.Field{
				Type:        graphql.NewList(hitType),
				Description: "Full-text search across indexed assets and findings (requires OpenSearch).",
				Args: graphql.FieldConfigArgument{
					"query": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"size":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 25},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return a.search.Search(p.Context, p.Args["query"].(string), p.Args["size"].(int))
				},
			},
			"posture": &graphql.Field{
				Type:        postureType,
				Description: "High-level posture summary for the overview dashboard.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.store.Snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					paths := a.analyzer.Latest()
					runtime := 0
					for _, ap := range paths {
						if ap.RuntimeConfirmed {
							runtime++
						}
					}
					return map[string]any{
						"criticalPaths":    len(paths),
						"runtimeConfirmed": runtime,
						"policyViolations": len(a.analyzer.Violations()),
						"nodes":            len(snap.Nodes),
						"edges":            len(snap.Edges),
					}, nil
				},
			},
			"graph": &graphql.Field{
				Type:        graphViewType,
				Description: "The full node/edge view for graph visualization.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.store.Snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					return map[string]any{"nodes": snap.Nodes, "edges": snap.Edges}, nil
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{Query: query})
}

// Typed resolver helpers keep the schema definition terse and type-safe.
func nodeField(f func(ontology.Node) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(ontology.Node)), nil }
}
func edgeField(f func(ontology.Edge) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(ontology.Edge)), nil }
}
func stepField(f func(analyzer.Step) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(analyzer.Step)), nil }
}
func pathField(f func(analyzer.AttackPath) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(analyzer.AttackPath)), nil }
}
func violationField(f func(policy.Violation) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(policy.Violation)), nil }
}
func suggestionField(f func(remediation.Suggestion) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(remediation.Suggestion)), nil }
}
func hitField(f func(search.Hit) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(search.Hit)), nil }
}
