package ontology

import (
	"encoding/json"
	"strings"
	"testing"
)

// NewID's determinism is what lets two collectors that saw the same asset upsert one
// node instead of creating two. If it ever stops being a pure function of (label, key
// parts), the graph silently duplicates every asset observed by more than one source.
func TestNewIDIsDeterministic(t *testing.T) {
	a := NewID(LabelContainer, "payments", "sha256:abc")
	b := NewID(LabelContainer, "payments", "sha256:abc")
	if a != b {
		t.Fatalf("same inputs produced %q and %q - the graph would duplicate this asset", a, b)
	}
}

// Collectors disagree on case (an ARN from one API, the same name lower-cased from
// another), so the key is folded before hashing.
func TestNewIDIgnoresCaseOfKeyParts(t *testing.T) {
	if got, want := NewID(LabelVirtualMachine, "Web-01"), NewID(LabelVirtualMachine, "web-01"); got != want {
		t.Errorf("case changed the id: %q vs %q", got, want)
	}
}

func TestNewIDSeparatesByLabelAndKey(t *testing.T) {
	base := NewID(LabelContainer, "payments")
	if same := NewID(LabelVirtualMachine, "payments"); same == base {
		t.Error("different labels produced the same id")
	}
	if same := NewID(LabelContainer, "billing"); same == base {
		t.Error("different keys produced the same id")
	}
}

// The id carries its label as a readable prefix, so a node id is self-describing in
// logs and in the API without a lookup.
func TestNewIDIsPrefixedByItsLabel(t *testing.T) {
	id := NewID(LabelVPC, "vpc-123")
	prefix := string(LabelVPC) + ":"
	if !strings.HasPrefix(id, prefix) {
		t.Fatalf("id %q does not start with %q", id, prefix)
	}
	if hash := strings.TrimPrefix(id, prefix); len(hash) != 16 {
		t.Errorf("hash part %q is %d chars, want 16", hash, len(hash))
	}
}

// Documented characteristic, not an endorsement: key parts are joined with "|" before
// hashing, so a part that itself contains "|" can collide with a differently-split key.
// Natural keys in practice are ARNs, image refs and CIDRs, none of which use it - but
// a collector that starts emitting pipes in a key needs to know this is here.
func TestNewIDJoinsPartsWithPipeAndCanCollideOnIt(t *testing.T) {
	split := NewID(LabelContainer, "a", "b")
	joined := NewID(LabelContainer, "a|b")
	if split != joined {
		t.Skip("separator behaviour changed - if parts are now escaped, delete this test")
	}
	t.Log("known: NewID(l, \"a\", \"b\") == NewID(l, \"a|b\"); avoid \"|\" inside a key part")
}

func TestIsValidLabelAndEdgeType(t *testing.T) {
	if !IsValidLabel(LabelContainer) {
		t.Error("a declared label was rejected")
	}
	if IsValidLabel(Label("NotARealLabel")) {
		t.Error("an unknown label was accepted - the allow-list is not closed")
	}
	if !IsValidEdgeType(EdgeHosts) {
		t.Error("a declared edge type was rejected")
	}
	if IsValidEdgeType(EdgeType("NOT_REAL")) {
		t.Error("an unknown edge type was accepted")
	}
	if IsValidLabel(Label("")) || IsValidEdgeType(EdgeType("")) {
		t.Error("empty accepted as valid")
	}
}

func TestNodeBoolDefaultsToFalse(t *testing.T) {
	n := Node{Properties: map[string]any{"internet_exposed": true, "count": 3, "name": "x"}}
	if !n.Bool("internet_exposed") {
		t.Error("a true property read as false")
	}
	if n.Bool("count") {
		t.Error("a non-bool property read as true")
	}
	if n.Bool("missing") {
		t.Error("a missing property read as true")
	}
	if (Node{}).Bool("anything") {
		t.Error("a node with no properties map panicked or read true")
	}
}

// The event is the wire contract between every collector and the bus, so it has to
// survive a JSON round trip unchanged - including an empty tenant, which means "the
// default tenant" and must not become a literal empty tenant downstream.
func TestEventRoundTripsThroughJSON(t *testing.T) {
	in := Event{
		Source: "trivy",
		Kind:   Kind("scan"),
		Nodes:  []Node{{ID: NewID(LabelContainer, "payments"), Label: LabelContainer, Name: "payments"}},
		Edges:  []Edge{{Type: EdgeHosts, From: "a", To: "b"}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"tenant"`) {
		t.Error("an empty tenant was serialized; it must be omitted so it stays 'the default'")
	}
	var out Event
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Source != in.Source || len(out.Nodes) != 1 || len(out.Edges) != 1 {
		t.Fatalf("round trip changed the event: %+v", out)
	}
	if out.Nodes[0].ID != in.Nodes[0].ID || out.Edges[0].Type != EdgeHosts {
		t.Errorf("round trip changed identity: %+v", out.Nodes[0])
	}
}

// ScopedID has two jobs and they pull in opposite directions: separate the same native
// identifier in different accounts, and leave a single-account estate's ids exactly as
// they were - otherwise the first upgrade orphans every node in the graph.
func TestScopedID(t *testing.T) {
	a := ScopedID(LabelVirtualMachine, "111111111111", "i-shared")
	b := ScopedID(LabelVirtualMachine, "222222222222", "i-shared")
	if a == b {
		t.Error("two accounts produced one id for the same instance id")
	}
	if got, want := ScopedID(LabelVirtualMachine, "", "i-legacy"), NewID(LabelVirtualMachine, "i-legacy"); got != want {
		t.Errorf("no account should mean the plain id: got %s, want %s", got, want)
	}
	// The account is a key part, not a prefix glued onto the hash input in a way that a
	// crafted instance id could imitate.
	if ScopedID(LabelVirtualMachine, "111", "i-x") == NewID(LabelVirtualMachine, "account=111", "i-x") {
		return // this IS the construction; asserted so a change to it is deliberate
	}
	t.Error("ScopedID no longer keys on the account as its first key part")
}
