package config

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A scanner report crosses up to three proxies before the backend reads it - the Helm
// ingress, the dashboard's nginx (compose's and the chart's) - and each has a body limit
// of its own. The backend accepts 32 MiB; a proxy that stops short answers 413 for a
// report the engine would have taken, and the pipeline that posted it reads a refusal
// from a component nobody thinks of. ingress-nginx's 1 MiB default did exactly that to
// every real report sent through the chart's ingress.
//
// So the limits are held to the backend's, which is the one that means something.
func TestProxiesPassEveryReportTheBackendAccepts(t *testing.T) {
	root := repoRoot(t)

	mib := func(name, src, pattern string) int {
		t.Helper()
		m := regexp.MustCompile(pattern).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s: no body limit found (pattern %s) - the extraction has drifted from the file", name, pattern)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return n
	}

	ingest := mib("ingestion/server.go", mustRead(t, root, "backend", "internal", "ingestion", "server.go"),
		`maxIngestBody = (\d+) << 20`)
	gate := mib("api/gate.go", mustRead(t, root, "backend", "internal", "api", "gate.go"),
		`gateMaxBody = (\d+) << 20`)
	if ingest != gate {
		t.Fatalf("the ingest webhook takes %d MiB and the gate %d MiB; they take the same reports", ingest, gate)
	}

	for _, proxy := range []struct {
		name, src, pattern string
	}{
		{"deploy/helm values.yaml ingress.maxBodySize",
			mustRead(t, root, "deploy", "helm", "perspectivegraph", "values.yaml"), `(?m)^  maxBodySize: (\d+)m$`},
		{"frontend/nginx.conf location /gate/",
			locationBlock(t, mustRead(t, root, "frontend", "nginx.conf"), "/gate/"), `client_max_body_size (\d+)m;`},
		{"deploy/helm frontend.yaml location /gate/",
			locationBlock(t, mustRead(t, root, "deploy", "helm", "perspectivegraph", "templates", "frontend.yaml"), "/gate/"),
			`client_max_body_size (\d+)m;`},
	} {
		if got := mib(proxy.name, proxy.src, proxy.pattern); got != ingest {
			t.Errorf("%s passes %d MiB, the backend accepts %d MiB", proxy.name, got, ingest)
		}
	}
}

// locationBlock returns an nginx location block's body: the lines after `location <path> {`
// up to the line that closes it. Line by line, because the chart's copy is a template whose
// {{ }} braces defeat a brace-matching pattern.
func locationBlock(t *testing.T, src, path string) string {
	t.Helper()
	var b strings.Builder
	in := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !in && trimmed == "location "+path+" {":
			in = true
		case in && trimmed == "}":
			return b.String()
		case in:
			b.WriteString(line + "\n")
		}
	}
	t.Fatalf("no `location %s { ... }` block", path)
	return ""
}
