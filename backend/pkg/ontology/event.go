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
	// Snapshot, when set, declares this event part of a COMPLETE description of one
	// scope for its source: whatever the source asserted in that scope before and no
	// longer lists is retracted once the whole ingest has reached the graph. Nil is a
	// partial observation - it adds and updates, and never takes anything away.
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Snapshot is a source's declaration that it has described Scope in full.
//
// The scope says how far "in full" reaches: one scanned image ("image:<ref>"), one
// repository, one AWS account and region. It is chosen by whoever can vouch for the
// completeness - a collector that knows it read a whole image, a connector that read a
// whole account, an operator posting a whole cluster - and by nobody else: a scope
// wider than what was actually read makes the engine forget assets that still exist.
//
// Taken is when the engine received the snapshot. It orders two snapshots of the same
// scope, so an older one landing late never undoes a newer one; it is set by the
// engine, not by the sender.
type Snapshot struct {
	Scope string    `json:"scope"`
	Taken time.Time `json:"taken"`
}

// Scope prefixes a collector uses for the scopes it can vouch for. The engine normalizes
// an image scope's reference as it normalizes the image's id.
const (
	ImageScopePrefix      = "image:"
	RepositoryScopePrefix = "repository:"
)

// MaxScopeLen bounds a snapshot scope: it is an identifier, not a payload.
const MaxScopeLen = 256

// ValidScope reports whether s can name a snapshot scope: non-empty, bounded, and
// printable ASCII - it lands in logs, metrics and SQL parameters.
func ValidScope(s string) bool {
	if s == "" || len(s) > MaxScopeLen {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// CompleteSnapshot is the event's snapshot declaration if it stands, nil if the event is
// a partial observation: no declaration, a scope that is not one, or a pull request's
// event - which describes a change that may never be merged, and must never retract what
// runs. The normalizer records origins by it and the broker schedules sweeps by it, so the
// two cannot disagree about what an event may retract.
func (ev Event) CompleteSnapshot() *Snapshot {
	if ev.Snapshot == nil || !ValidScope(ev.Snapshot.Scope) || ev.CarriesPRContext() {
		return nil
	}
	return ev.Snapshot
}

// CarriesPRContext reports whether any node of the event is stamped with a pull
// request: a commit or a pull-request number. Such an event describes a change that
// may never be merged, not what runs, so it must never retract anything. A repository
// slug alone is not PR context - build provenance names the repository an image was
// built from.
func (ev Event) CarriesPRContext() bool {
	for _, n := range ev.Nodes {
		if sha, _ := n.Properties[PropCommitSHA].(string); sha != "" {
			return true
		}
		switch v := n.Properties[PropPRNumber].(type) {
		case int:
			if v > 0 {
				return true
			}
		case int64:
			if v > 0 {
				return true
			}
		case float64:
			if v > 0 {
				return true
			}
		case string:
			if v != "" && v != "0" {
				return true
			}
		}
	}
	return false
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

// IsSeed reports whether an attack may start at n: it is reachable from the internet,
// open to anyone, or - under the opt-in credential-origin lens - an identity whose
// credentials are assumed leaked. Every engine that picks where attacks begin asks this
// one question, so the path list, the risk simulation and the alternative routes cannot
// disagree about it again: the credential-origin seeds were once honoured by the path
// search alone.
func (n Node) IsSeed() bool {
	return n.Bool(PropInternetExposed) || n.Bool(PropCredentialExposed) || n.Bool(PropPublicAccess)
}

// HeldByAttacker reports whether an attacker holds n without crossing a single edge:
// anyone may use it (a public-read bucket, a role any principal may assume), or its
// credentials are assumed leaked. Reachable is not held - an internet-facing database
// still wants a password - so a crown jewel that is merely reachable counts as
// compromised only when an edge reaches it, and one that is held counts at once.
func (n Node) HeldByAttacker() bool {
	return n.Bool(PropPublicAccess) || n.Bool(PropCredentialExposed)
}
