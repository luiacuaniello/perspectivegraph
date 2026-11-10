package api

import (
	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/attck"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The graph itself: its nodes and edges, the applications drawn over it, and the full-text search into it.

func (a *API) graphTypes(t *schemaTypes) {
	nodeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Node",
		Fields: graphql.Fields{
			"id":                     &graphql.Field{Type: graphql.NewNonNull(graphql.String), Resolve: field[ontology.Node](func(n ontology.Node) any { return n.ID })},
			"label":                  &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return string(n.Label) })},
			"name":                   &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Name })},
			"internetExposed":        &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.InternetExposed() })},
			"exposedPorts":           &graphql.Field{Type: graphql.String, Description: "What the internet reaches of this asset, as its firewalls decide it port by port: \"tcp/22, tcp/443\". Absent when it is not exposed or no source says which ports.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties["exposed_ports"] })},
			"exposedManagementPorts": &graphql.Field{Type: graphql.String, Description: "The part of exposedPorts that is a remote shell, a control plane or a database (SSH, RDP, the Kubernetes API, PostgreSQL…).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties["exposed_management_ports"] })},
			"crownJewel":             &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropCrownJewel) })},
			"account":                &graphql.Field{Type: graphql.String, Description: "Cloud account the asset belongs to (AWS account id, subscription, project). Native identifiers like i-… are unique only within one account, so this is part of the node's identity for infrastructure and is read off the ARN for identities. Empty on a single-account estate that does not send one.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropAccount] })},
			"crownJewelBasis":        &graphql.Field{Type: graphql.String, Description: "Why this node is a crown jewel: \"tagged\" (explicit), \"classified:<source>:<kind>\" (a real classifier - Macie/DLP), or \"inferred:<signal>\" (guessed from a sensitive-data signal).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropCrownJewelBasis] })},
			"classification":         &graphql.Field{Type: graphql.String, Description: "Data classification from a real classifier (Macie/DLP/tag policy): pii|phi|pci|financial|secret|…", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropClassification] })},
			"secretsScrubbed":        &graphql.Field{Type: graphql.Boolean, Description: "True when a secret-looking value (token, key, password) was redacted out of this node's properties at ingest. The finding is kept; the credential is not - so the attack map never hands out a live secret.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropSecretsScrubbed) })},
			"runtimeAlert":           &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropRuntimeAlert) })},
			"severity":               &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSeverity] })},
			"cvss":                   &graphql.Field{Type: graphql.Float, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropCVSS] })},
			"kev":                    &graphql.Field{Type: graphql.Boolean, Description: "In CISA's Known Exploited Vulnerabilities catalog (exploited in the wild).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropKEV) })},
			"epss":                   &graphql.Field{Type: graphql.Float, Description: "FIRST EPSS probability of exploitation within 30 days, [0,1].", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropEPSS] })},
			"resolutionMethod":       &graphql.Field{Type: graphql.String, Description: "How this node's identity was inferred by the resolver (digest|tag|name). Absent when the identity was asserted by a tool, not inferred.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionMethod] })},
			"resolutionConfidence":   &graphql.Field{Type: graphql.Float, Description: "How confident the inferred identity/join is, [0,1]. <1 means a heuristic correlation an analyst should verify.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionConfidence] })},
			"resolutionAlias":        &graphql.Field{Type: graphql.String, Description: "The raw reference that was matched to produce this inferred identity.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionAlias] })},
			"signed":                 &graphql.Field{Type: graphql.Boolean, Description: "Supply-chain: image signature verified (cosign). Null when never assessed - distinct from false (verified unsigned).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSigned] })},
			"slsaLevel":              &graphql.Field{Type: graphql.Int, Description: "Supply-chain: SLSA build-provenance level [0..4]; higher is a more trustworthy build.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSLSALevel] })},
			"sbomComponents":         &graphql.Field{Type: graphql.Int, Description: "Supply-chain: number of SBOM components recorded for this image.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSBOMComponents] })},
		},
	})

	// MITRE ATT&CK technique a hop maps to (a documented best-fit heuristic).
	attackType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "AttackTechnique",
		Description: "The MITRE ATT&CK technique this hop corresponds to (heuristic mapping from the edge type, not an observation).",
		Fields: graphql.Fields{
			"id":       &graphql.Field{Type: graphql.String, Description: "Technique ID, e.g. T1190 or T1078.004.", Resolve: field[attck.Technique](func(t attck.Technique) any { return t.ID })},
			"name":     &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.Name })},
			"tactic":   &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.Tactic })},
			"tacticId": &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.TacticID })},
			"url":      &graphql.Field{Type: graphql.String, Description: "Canonical MITRE ATT&CK page.", Resolve: field[attck.Technique](func(t attck.Technique) any { return t.URL() })},
		},
	})

	edgeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Edge",
		Fields: graphql.Fields{
			"type":        &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return string(e.Type) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.ExploitProbability })},
			"attack": &graphql.Field{Type: attackType, Resolve: field[ontology.Edge](func(e ontology.Edge) any {
				if t, ok := attck.ForEdge(e.Type); ok {
					return t
				}
				return nil
			})},
		},
	})

	stepType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPathStep",
		Fields: graphql.Fields{
			"edgeType":    &graphql.Field{Type: graphql.String, Resolve: field[stepView](func(s stepView) any { return string(s.EdgeType) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: field[stepView](func(s stepView) any { return s.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: field[stepView](func(s stepView) any { return s.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: field[stepView](func(s stepView) any { return s.Probability })},
			"attack": &graphql.Field{Type: attackType, Description: "The MITRE ATT&CK technique this hop maps to, read in the context of its route: initial access is credited to the hop where access is gained (the exploit when the route has one), and an exploit after the attacker is inside is lateral movement. Nil for structural hops - a library that has a CVE, an image that ships a library.", Resolve: field[stepView](func(s stepView) any {
				if s.technique == nil {
					return nil
				}
				return *s.technique
			})},
			"resolutionMethod": &graphql.Field{Type: graphql.String, Description: "Set when this hop's join was inferred by the resolver (digest|tag|name); absent for a hard, tool-asserted edge.", Resolve: field[stepView](func(s stepView) any {
				if s.ResolutionMethod == "" {
					return nil
				}
				return s.ResolutionMethod
			})},
			"resolutionConfidence": &graphql.Field{Type: graphql.Float, Description: "How confident this inferred hop is, [0,1]. <1 means a heuristic correlation to verify (and the probability is already discounted for it).", Resolve: field[stepView](func(s stepView) any {
				if s.ResolutionMethod == "" {
					return nil
				}
				return s.ResolutionConfidence
			})},
			"weightBasis":      &graphql.Field{Type: graphql.String, Description: "Where this hop's probability came from: kev|epss|runtime (evidence) vs cvss|severity|heuristic (estimate).", Resolve: field[stepView](func(s stepView) any { return s.WeightBasis })},
			"weightConfidence": &graphql.Field{Type: graphql.Float, Description: "How much to trust this hop's probability, [0,1], given its basis.", Resolve: field[stepView](func(s stepView) any { return s.WeightConfidence })},
		},
	})

	t.nodeType = nodeType
	t.attackType = attackType
	t.edgeType = edgeType
	t.stepType = stepType
}

func (a *API) estateQueries(t *schemaTypes) graphql.Fields {
	hitType, graphViewType := t.hitType, t.graphViewType
	return graphql.Fields{
		"applications": &graphql.Field{
			Type:        graphql.NewList(graphql.String),
			Description: "Distinct application identifiers in the graph (repo slugs and app tags), for scoping queries.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				snap, err := a.view(p.Context).snapshot()
				if err != nil {
					return nil, err
				}
				return applications(snap), nil
			},
		},
		"graph": &graphql.Field{
			Type:        graphViewType,
			Description: "The node/edge view for graph visualization, optionally scoped to one application and paginated.",
			Args: graphql.FieldConfigArgument{
				"app":    &graphql.ArgumentConfig{Type: graphql.String, Description: "Keep the connected component(s) around this application's nodes."},
				"limit":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
				"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				snap, err := a.view(p.Context).snapshot()
				if err != nil {
					return nil, err
				}
				nodes, edges := snap.Nodes, snap.Edges
				app, _ := p.Args["app"].(string)
				if app != "" {
					nodes, edges = filterByApp(snap, app)
				}
				limit, _ := p.Args["limit"].(int)
				offset, _ := p.Args["offset"].(int)
				nodes, edges = paginate(nodes, edges, limit, offset)
				a.auditView(p.Context, "view.graph", map[string]any{
					"nodes": len(nodes), "edges": len(edges), "app": app,
				})
				return map[string]any{"nodes": nodes, "edges": edges}, nil
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
				return a.view(p.Context).find(p.Args["query"].(string), p.Args["size"].(int))
			},
		},
		"searchEnabled": &graphql.Field{
			Type:        graphql.Boolean,
			Description: "Whether full-text search (OpenSearch) is configured. The UI uses this to tell “feature off” apart from “no matches”.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).searchEnabled(), nil
			},
		},
		"aiEnabled": &graphql.Field{
			Type:        graphql.Boolean,
			Description: "Whether the AI-native layer (ANTHROPIC_API_KEY) is configured and open to this caller - it is not to an anonymous visitor of a read-only instance. The UI uses this to show/hide the AI assistant, summary, and explain features.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.aiAvailableTo(p.Context), nil
			},
		},
	}
}
