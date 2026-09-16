package config

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The MCP Registry entry is generated per release by scripts/mcp-server-json.sh and
// published by the mcp-registry job, and nothing in the registry's own validation knows
// what this binary actually accepts. It checks the JSON against its schema; it cannot know
// that `perspectivegraph mcp` has no `--url` flag, or that the image label says a different
// name. Every field below is one of those facts, held to the file that defines it.
func TestMCPRegistryEntry(t *testing.T) {
	requireBash(t)
	root := repoRoot(t)
	read := func(parts ...string) string {
		return mustRead(t, append([]string{root}, parts...)...)
	}

	const version = "9.8.7"
	out, err := exec.Command("bash", filepath.Join(root, "scripts", "mcp-server-json.sh"), version).Output()
	if err != nil {
		t.Fatalf("scripts/mcp-server-json.sh %s: %v", version, err)
	}
	var entry struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Packages []struct {
			RegistryType string `json:"registryType"`
			Identifier   string `json:"identifier"`
			Transport    struct {
				Type string `json:"type"`
			} `json:"transport"`
			PackageArguments []struct {
				Type  string `json:"type"`
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"packageArguments"`
			EnvironmentVariables []struct {
				Name string `json:"name"`
			} `json:"environmentVariables"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(out, &entry); err != nil {
		t.Fatalf("the script does not print valid JSON: %v\n%s", err, out)
	}
	if len(entry.Packages) != 1 {
		t.Fatalf("entry has %d packages, want the one backend image", len(entry.Packages))
	}
	pkg := entry.Packages[0]

	// The registry refuses an image whose label names a different server.
	label := regexp.MustCompile(`(?m)^LABEL io\.modelcontextprotocol\.server\.name="([^"]+)"$`).FindStringSubmatch(read("backend", "Dockerfile"))
	if label == nil {
		t.Fatal("backend/Dockerfile has no io.modelcontextprotocol.server.name label; the registry cannot list the image without it")
	}
	if entry.Name != label[1] {
		t.Errorf("entry name %q, but the image label says %q - the registry would refuse the publish", entry.Name, label[1])
	}

	// The version and tag are the release, and the image is the one publish-images pushes
	// from ./backend.
	if entry.Version != version {
		t.Errorf("entry version %q, want %q", entry.Version, version)
	}
	workflow := read(".github", "workflows", "publish-images.yml")
	backend := regexp.MustCompile(`context: \./backend\s+image: (\S+)`).FindStringSubmatch(workflow)
	if backend == nil {
		t.Fatal("publish-images.yml has no matrix entry building ./backend")
	}
	if want := "ghcr.io/luiacuaniello/" + backend[1] + ":v" + version; pkg.Identifier != want {
		t.Errorf("entry image %q, want %q - the image publish-images pushes for this release", pkg.Identifier, want)
	}
	if pkg.RegistryType != "oci" || pkg.Transport.Type != "stdio" {
		t.Errorf("package is %s over %s, want an oci image over stdio", pkg.RegistryType, pkg.Transport.Type)
	}

	// The arguments a client will pass must be ones `perspectivegraph mcp` accepts.
	mcpGo := read("backend", "cmd", "perspectivegraph", "mcp.go")
	if len(pkg.PackageArguments) == 0 || pkg.PackageArguments[0].Type != "positional" || pkg.PackageArguments[0].Value != "mcp" {
		t.Errorf("the first package argument must be the positional `mcp` subcommand, got %+v", pkg.PackageArguments)
	}
	for _, a := range pkg.PackageArguments {
		if a.Type != "named" {
			continue
		}
		flag := strings.TrimLeft(a.Name, "-")
		if !strings.Contains(mcpGo, `fs.String("`+flag+`"`) {
			t.Errorf("entry passes %s, but `perspectivegraph mcp` defines no such flag", a.Name)
		}
	}
	for _, v := range pkg.EnvironmentVariables {
		if !strings.Contains(mcpGo, `"`+v.Name+`"`) {
			t.Errorf("entry documents %s, but `perspectivegraph mcp` never reads it", v.Name)
		}
	}

	// The job publishes what the script renders, under the same name, with a pinned tool.
	for what, re := range map[string]string{
		"publishes under the entry's name":       `SERVER_NAME: ` + regexp.QuoteMeta(entry.Name) + `\n`,
		"renders the entry with the script":      `bash scripts/mcp-server-json\.sh "\$\{TAG#v\}" > server\.json`,
		"logs in with GitHub OIDC, not a secret": `mcp-publisher login github-oidc`,
		"pins mcp-publisher by sha256":           `MCP_PUBLISHER_SHA256: [0-9a-f]{64}\n`,
		"asks the registry before publishing":    `/versions/\$\{version\}`,
		"may request the OIDC token":             `id-token: write # mcp-publisher login github-oidc`,
	} {
		if !regexp.MustCompile(re).MatchString(workflow) {
			t.Errorf("publish-images.yml mcp-registry job no longer %s (%s)", what, re)
		}
	}

	// A prerelease or a "v"-prefixed tag must not render: the job strips the v, and a
	// prerelease would become the version every registry client installs.
	for _, bad := range []string{"v" + version, "1.2", "1.2.3-rc.1"} {
		if err := exec.Command("bash", filepath.Join(root, "scripts", "mcp-server-json.sh"), bad).Run(); err == nil {
			t.Errorf("scripts/mcp-server-json.sh accepted %q", bad)
		}
	}
}
