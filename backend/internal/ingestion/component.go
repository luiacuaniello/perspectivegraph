package ingestion

import (
	"net/url"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// ComponentID is the node id of a software component an image ships: the package name a
// vulnerability scanner reports, and its version. Trivy and an SBOM both describe what an
// image contains, so they must key a component the same way or the vulnerable library
// Trivy found and the one the SBOM listed are two nodes that never meet.
func ComponentID(label ontology.Label, name, version string) string {
	return ontology.NewID(label, name, version)
}

// DependsOnProb is the probability on image --DEPENDS_ON--> component: the attacker who
// holds the image holds what it ships. Every source writing that edge uses it, so the edge
// does not depend on which source was written last.
const DependsOnProb = 0.95

// ScannerName is the name a vulnerability scanner gives the package a PURL identifies.
// Trivy names a Maven package groupId:artifactId and an npm, Composer or Go package by its
// full path; a PURL splits those into namespace and name. For every other ecosystem the
// namespace is not part of the name - a Debian PURL's namespace is the distribution - so
// the name alone is the scanner's. It returns "" when the PURL cannot be read.
func ScannerName(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if at := strings.LastIndex(rest, "@"); at > strings.LastIndex(rest, "/") {
		rest = rest[:at]
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || path == "" {
		return ""
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if u, err := url.PathUnescape(s); err == nil {
			segs[i] = u
		}
	}
	name := segs[len(segs)-1]
	namespace := strings.Join(segs[:len(segs)-1], "/")
	if namespace == "" {
		return name
	}
	switch strings.ToLower(typ) {
	case "maven":
		return namespace + ":" + name
	case "npm", "composer", "golang":
		return namespace + "/" + name
	}
	return name
}
