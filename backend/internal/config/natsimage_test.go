package config

import (
	"regexp"
	"testing"
)

// samePin fails unless every file pins the image exactly once, and all of them the same
// tag and digest.
func samePin(t *testing.T, image string, pin *regexp.Regexp, files [][]string) {
	t.Helper()
	root := repoRoot(t)
	var want, wantFrom string
	for _, file := range files {
		name := file[len(file)-1]
		found := pin.FindAllString(mustRead(t, append([]string{root}, file...)...), -1)
		if len(found) != 1 {
			t.Errorf("%s pins %s %d times, want exactly once (tag and digest): %v", name, image, len(found), found)
			continue
		}
		if want == "" {
			want, wantFrom = found[0], name
			continue
		}
		if found[0] != want {
			t.Errorf("%s pins %s, but %s pins %s - run `make sync-pins`", name, found[0], wantFrom, want)
		}
	}
}

// NATS is pinned by tag AND digest in four places that no tool keeps together: the compose
// stack, the chart's default, the image list Artifact Hub scans and reports on the chart's
// page, and the CI job that runs the store contract test against a real broker. A bump
// that reaches some of them - Dependabot updates the chart's values, not a chart
// annotation or a workflow's docker run - leaves the badge scoring an image nobody deploys,
// or the tests exercising a broker the release does not ship. The Node pin broke exactly
// that way. `make sync-pins` carries the values' pin to the other three.
func TestNATSImageIsTheSameEverywhere(t *testing.T) {
	samePin(t, "NATS", regexp.MustCompile(`nats:[0-9][^\s@"']*@sha256:[0-9a-f]{64}`), [][]string{
		{"deploy", "helm", "perspectivegraph", "values.yaml"},
		{"docker-compose.yml"},
		{"deploy", "helm", "perspectivegraph", "Chart.yaml"},
		{".github", "workflows", "ci.yml"},
	})
}

// Keycloak, the IdP of the SSO demo, is pinned in the compose stack and in the Kubernetes
// manifest of the same demo. Dependabot reads only the compose file, and the manifest fell
// two digests behind before anything said so. `make sync-pins` carries the compose pin to
// the manifest.
func TestKeycloakImageIsTheSameEverywhere(t *testing.T) {
	samePin(t, "Keycloak", regexp.MustCompile(`quay\.io/keycloak/keycloak:[0-9][^\s@"']*@sha256:[0-9a-f]{64}`), [][]string{
		{"docker-compose.yml"},
		{"deploy", "keycloak", "k8s-keycloak-demo.yaml"},
	})
}
