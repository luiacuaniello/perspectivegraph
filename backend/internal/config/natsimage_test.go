package config

import (
	"regexp"
	"testing"
)

// NATS is pinned by tag AND digest in four places that no tool keeps together: the compose
// stack, the chart's default, the image list Artifact Hub scans and reports on the chart's
// page, and the CI job that runs the store contract test against a real broker. A bump
// that reaches some of them - Dependabot updates compose and values, not a chart annotation
// or a workflow's docker run - leaves the badge scoring an image nobody deploys, or the
// tests exercising a broker the release does not ship. The Node pin broke exactly that way.
func TestNATSImageIsTheSameEverywhere(t *testing.T) {
	root := repoRoot(t)
	pin := regexp.MustCompile(`nats:[0-9][^\s@"']*@sha256:[0-9a-f]{64}`)

	var want, wantFrom string
	for _, file := range [][]string{
		{"docker-compose.yml"},
		{"deploy", "helm", "perspectivegraph", "values.yaml"},
		{"deploy", "helm", "perspectivegraph", "Chart.yaml"},
		{".github", "workflows", "ci.yml"},
	} {
		name := file[len(file)-1]
		found := pin.FindAllString(mustRead(t, append([]string{root}, file...)...), -1)
		if len(found) != 1 {
			t.Errorf("%s pins NATS %d times, want exactly once (tag and digest): %v", name, len(found), found)
			continue
		}
		if want == "" {
			want, wantFrom = found[0], name
			continue
		}
		if found[0] != want {
			t.Errorf("%s pins %s, but %s pins %s", name, found[0], wantFrom, want)
		}
	}
}
