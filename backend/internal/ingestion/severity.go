package ingestion

import "strings"

// SeverityProbability is the single severity → exploit-probability scale every
// collector maps onto. Tools normalize their native levels to
// CRITICAL/HIGH/MEDIUM/LOW first (see each collector), then call this - so an
// edge weight means the same thing no matter which scanner produced it.
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
