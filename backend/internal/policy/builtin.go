package policy

import "github.com/aegisgraph/aegisgraph/pkg/ontology"

// Builtins returns the default architectural invariants AegisGraph ships with.
// Teams extend these with their own via Engine.Add.
func Builtins() []Invariant {
	internetExposed := func(n ontology.Node) bool { return n.Bool(ontology.PropInternetExposed) }
	crownJewel := func(n ontology.Node) bool { return n.Bool(ontology.PropCrownJewel) }

	return []Invariant{
		{
			ID:          "no-internet-to-crown-jewel",
			Description: "No internet-exposed asset may have a path to a crown-jewel asset.",
			Severity:    "CRITICAL",
			Source:      internetExposed,
			Target:      crownJewel,
		},
		{
			ID:          "no-internet-to-secret",
			Description: "No internet-exposed asset may reach an exposed secret.",
			Severity:    "HIGH",
			Source:      internetExposed,
			Target:      func(n ontology.Node) bool { return n.Label == ontology.LabelSecret },
		},
		{
			ID:          "no-public-data-store",
			Description: "Object storage and managed databases must not be internet-exposed.",
			Severity:    "HIGH",
			Source:      nil, // node-level
			Target: func(n ontology.Node) bool {
				return (n.Label == ontology.LabelBucket || n.Label == ontology.LabelDatabase) &&
					n.Bool(ontology.PropInternetExposed)
			},
		},
	}
}
