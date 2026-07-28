package ingestion

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// SeverityProbability is the single severity → exploit-probability scale every
// collector maps onto. Tools normalize their native levels to
// CRITICAL/HIGH/MEDIUM/LOW first (see each collector), then call this - so an
// edge weight means the same thing no matter which scanner produced it.
//
// These anchors (0.9/0.7/0.4/0.2) are deliberate *heuristics*, not measured
// probabilities - which is why such hops carry weight_basis="severity" (low
// confidence) and feed the [score, scoreUpperBound] band. They are a reasonable
// monotone prior; the calibration loop is what tells you whether they're scaled
// right on real verdicts. Keep the ordering and the gaps; retune only with data.
func SeverityProbability(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0.9
	case "HIGH":
		return 0.7
	case "MEDIUM":
		return 0.4
	case "LOW":
		return 0.2
	default:
		return 0.1 // unknown: traversable but cheap
	}
}

// CrownJewelTagKeys / CrownJewelTagValues drive the data-driven crown-jewel
// classification: a resource is a crown jewel when any of these tag keys has
// one of these values (or the literal tag crown-jewel=true). Operators tag
// their cloud resources; PerspectiveGraph picks the tags up - no hardcoded
// resource names.
var (
	CrownJewelTagKeys   = []string{"classification", "data-classification", "data", "sensitivity"}
	CrownJewelTagValues = []string{"pii", "sensitive", "confidential", "restricted", "secret"}
)

// CrownJewelFromTags applies the classification rules to a resource tag map
// (keys lowercased by the caller or matched case-insensitively here).
// MarkCrownJewelFromTags applies the tag rules and, when they fire, records BOTH the
// flag and where it came from.
//
// The provenance is not decoration. A tag is the one crown-jewel signal an attacker can
// forge - `ec2:CreateTags` is granted freely because tagging looks harmless - and the
// analyzer deliberately ranks a tag-derived target below one an authoritative classifier
// vouched for. That ranking reads crown_jewel_basis, so a flag written without the basis
// silently claims authority the engine never observed.
//
// It exists as one helper because six ingestion sites mark crown jewels from tags, and
// six copies of "set the flag, remember to set the basis" is five chances to forget.
func MarkCrownJewelFromTags(props map[string]any, tags map[string]string) bool {
	if !CrownJewelFromTags(tags) {
		return false
	}
	props[ontology.PropCrownJewel] = true
	// An authoritative classifier may already have spoken for this node; a tag must
	// never demote what a real classifier established.
	if _, ok := props[ontology.PropCrownJewelBasis]; !ok {
		props[ontology.PropCrownJewelBasis] = ontology.CrownJewelBasisTagged
	}
	return true
}

func CrownJewelFromTags(tags map[string]string) bool {
	get := func(key string) string {
		for k, v := range tags {
			if strings.EqualFold(k, key) {
				return v
			}
		}
		return ""
	}
	if strings.EqualFold(get("crown-jewel"), "true") {
		return true
	}
	for _, key := range CrownJewelTagKeys {
		v := strings.ToLower(get(key))
		if v == "" {
			continue
		}
		for _, want := range CrownJewelTagValues {
			if v == want {
				return true
			}
		}
	}
	return false
}
