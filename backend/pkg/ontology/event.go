// Package ontology defines the common vocabulary of PerspectiveGraph: the node
// labels, edge types, and the normalized Event envelope that every collector
// emits onto the bus. It is the single contract shared by all layers.
package ontology

import (
	"crypto/sha1" // #nosec G505 -- sha1 for content-addressed node IDs (git-style), not a security primitive
	"encoding/hex"
	"strings"
	"time"
)

// Kind classifies what a collector observed.
type Kind string

const (
	KindAsset        Kind = "asset"        // a resource exists (container, role, repo…)
	KindFinding      Kind = "finding"      // a vulnerability / misconfiguration / secret
	KindRelationship Kind = "relationship" // a connection between assets
	KindRuntime      Kind = "runtime"      // a live runtime observation (Falco/eBPF)
)

// Node is a vertex in the graph. ID must be stable across observations so the
// normalization layer can deduplicate (upsert) rather than create duplicates.
type Node struct {
	ID         string         `json:"id"`
	Label      Label          `json:"label"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Edge is a directed relationship between two nodes, referenced by their IDs.
// ExploitProbability is p ∈ (0,1]: the likelihood an attacker can traverse this
// edge. The analyzer composes these into a path score S(P) = ∏ p.
type Edge struct {
	Type               EdgeType       `json:"type"`
	From               string         `json:"from"`
	To                 string         `json:"to"`
	ExploitProbability float64        `json:"exploit_probability,omitempty"`
	Properties         map[string]any `json:"properties,omitempty"`
}

// Event is the normalized envelope published to the bus by every collector.
// It is the only contract downstream layers consume.
type Event struct {
	Source     string    `json:"source"`
	Kind       Kind      `json:"kind"`
	ObservedAt time.Time `json:"observed_at"`
	// Tenant routes the event to a tenant's isolated graph. Empty ("") is
	// treated as the default tenant, so single-tenant deployments need not set
	// it. The ingest layer stamps it from the authenticated principal.
	Tenant string `json:"tenant,omitempty"`
	Nodes  []Node `json:"nodes"`
	Edges  []Edge `json:"edges"`
}

// NewID builds a deterministic node ID from a label and one or more natural-key
// parts. Two collectors observing the same asset with the same key produce the
// same ID, which is what lets the graph layer upsert instead of duplicate.
//
//	NewID(LabelContainer, "payments", "sha256:abc…")  // => "Container:9f8c…"
func NewID(label Label, keyParts ...string) string {
	h := sha1.New() // #nosec G401 -- sha1 for content-addressed node IDs (git-style), not a security primitive
	h.Write([]byte(strings.ToLower(strings.Join(keyParts, "|"))))
	return string(label) + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}

// ScopedID builds a node ID for an asset whose natural key is unique only within one
// cloud account, qualifying it with that account.
//
// Callers pass the account through unchanged when they do not know it (the empty string),
// which yields exactly the id NewID would have produced. That is deliberate: an operator
// who has not started sending accounts keeps the graph they already have, and one who
// starts sending them gets new nodes for the newly-distinguishable assets rather than a
// silent merge. Both are correct; a mix is what would be wrong, and it cannot happen for
// a given asset because the account either arrives with it or does not.
func ScopedID(label Label, account string, keyParts ...string) string {
	if account == "" {
		return NewID(label, keyParts...)
	}
	return NewID(label, append([]string{"account=" + account}, keyParts...)...)
}

// Bool reads a boolean node property, defaulting to false.
func (n Node) Bool(key string) bool {
	v, ok := n.Properties[key].(bool)
	return ok && v
}
