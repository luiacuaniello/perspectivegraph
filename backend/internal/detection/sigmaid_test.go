package detection

import (
	"regexp"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The Sigma spec defines `id` as a UUID, and converters validate it - a rule whose id is
// not a UUID can be refused at load time, which is the worst possible failure for a file
// somebody pasted into their SIEM believing it worked.
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestSigmaIDIsAValidV5UUID(t *testing.T) {
	for _, path := range []string{
		"ap-edge-alb-payments-admin-9ebc68f4",
		"ap-4705e5a88f55def0-ec84c244999b016f-41b11312",
		"",
	} {
		got := sigmaID(path)
		if !uuidRE.MatchString(got) {
			t.Errorf("sigmaID(%q) = %q - not a version-5 UUID with an RFC 4122 variant", path, got)
		}
	}
}

// Derived, not random: re-issuing the rule for the same route must update it in the SIEM
// rather than add a second copy of the same detection.
func TestSigmaIDIsStableForARoute(t *testing.T) {
	const path = "ap-edge-alb-payments-admin-9ebc68f4"
	first := sigmaID(path)
	for i := 0; i < 50; i++ {
		if got := sigmaID(path); got != first {
			t.Fatalf("sigmaID is not stable: %q then %q", first, got)
		}
	}
	if other := sigmaID("ap-edge-alb-customers-db-312e3ca3"); other == first {
		t.Error("two different routes produced the same rule id")
	}
}

// The implementation is hand-rolled - this repo takes no dependency for sixteen bytes -
// so it is checked against vectors computed by an INDEPENDENT implementation rather than
// against itself. Both come from Python's stdlib:
//
//	python3 -c "import uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, '<name>'))"
//
// A hand-rolled UUID that agrees with itself proves nothing; one that agrees with someone
// else's decoder is what makes the rule loadable in a SIEM we have never seen.
func TestUUIDV5MatchesIndependentImplementation(t *testing.T) {
	for name, want := range map[string]string{
		"https://www.example.com/": "3d3ed9d2-aa3d-5fa6-90e8-ed662e90f559",
		"https://github.com/luiacuaniello/perspectivegraph/rules/ap-edge-alb-payments-admin-9ebc68f4": "317a0bed-caa6-5a0c-a1ce-be8e4126b2b9",
	} {
		if got := uuidV5(urlNamespace, name); got != want {
			t.Errorf("uuidV5(URL namespace, %q) = %q, want %q - the derivation does not match RFC 4122", name, got, want)
		}
	}
}

// An opaque id is only acceptable because the readable path id survives in the tags: that
// is what lets an analyst take an alert back to the route that predicted it. Losing it
// would make the UUID a downgrade rather than a fix.
func TestSigmaRuleKeepsThePathIDInItsTags(t *testing.T) {
	const path = "ap-edge-alb-payments-admin-9ebc68f4"
	d := sigmaRule(
		ontology.Node{Label: ontology.LabelContainer, Name: "payments"},
		ontology.Node{Label: ontology.LabelIAMRole, Name: "payments-admin"},
		"",
		path,
	)
	if !strings.Contains(d.Content, "perspectivegraph.path."+path) {
		t.Errorf("the Sigma rule does not carry the path id in its tags:\n%s", d.Content)
	}
	if strings.Contains(d.Content, "id: perspectivegraph-") {
		t.Error("the Sigma rule still uses the old non-UUID id")
	}
}
