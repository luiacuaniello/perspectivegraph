package policy

import "github.com/luiacuaniello/perspectivegraph/pkg/ontology"

// Builtins returns the default architectural invariants PerspectiveGraph ships with.
// Teams extend these with their own via Engine.Add.
func Builtins() []Invariant {
	internetExposed := func(n ontology.Node) bool { return n.Bool(ontology.PropInternetExposed) }
	crownJewel := func(n ontology.Node) bool { return n.Bool(ontology.PropCrownJewel) }

	return []Invariant{
		{
			ID:          "no-internet-to-sensitive-asset",
			Description: "No internet-exposed asset may have a path to a sensitive asset.",
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
			ID:          "no-internet-to-unsigned-image",
			Description: "No internet-exposed asset may reach an unsigned image - an unsigned build is a tampering vector into a reachable workload.",
			Severity:    "HIGH",
			Source:      internetExposed,
			Target: func(n ontology.Node) bool {
				// Only *assessed* images count: PropSigned present and false. An image
				// with no supply-chain data is "unknown", not "unsigned".
				signed, assessed := n.Properties[ontology.PropSigned].(bool)
				return n.Label == ontology.LabelImage && assessed && !signed
			},
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
