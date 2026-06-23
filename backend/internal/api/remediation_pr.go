package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	remediationpkg "github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// WithRemediationPR attaches the opener that turns a path's generated fix into a
// real pull request (POST /remediation/pr). A nil opener disables the endpoint.
// Returns the API for chaining.
func (a *API) WithRemediationPR(opener action.PROpener) *API {
	a.prOpener = opener
	return a
}

type remediationPRRequest struct {
	PathID string `json:"pathId"`
}

// openRemediationPR handles POST /remediation/pr — generate the remediation for a
// path and open a pull request with it (branch + commit + PR). Admin-only, audited.
func (a *API) openRemediationPR(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to open a remediation PR")
		return
	}
	if a.prOpener == nil || !a.prOpener.Enabled() {
		writeJSONError(w, http.StatusServiceUnavailable, "remediation-as-PR is not configured (set GITHUB_TOKEN)")
		return
	}
	var req remediationPRRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.PathID == "" {
		writeJSONError(w, http.StatusBadRequest, "pathId is required")
		return
	}

	path, ok := findPath(a.scopedLatest(r.Context()), req.PathID)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "attack path not found (or out of your scope)")
		return
	}
	slug := repoSlugOf(path)
	if slug == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "no repository context on this path — cannot open a PR")
		return
	}
	suggestions := remediationpkg.Generate(path)
	if len(suggestions) == 0 {
		writeJSONError(w, http.StatusUnprocessableEntity, "no automatable remediation for this path")
		return
	}

	files := make([]action.PRFile, 0, len(suggestions))
	var body strings.Builder
	fmt.Fprintf(&body, "Automated remediation for attack path `%s` → **%s** (exploit score %.0f%%).\n\n",
		path.ID, path.Target().Name, path.Score*100)
	body.WriteString("Cutting any one edge breaks the path. This PR adds:\n\n")
	for _, s := range suggestions {
		files = append(files, action.PRFile{Path: s.Filename, Content: s.Content})
		fmt.Fprintf(&body, "- `%s` — %s\n", s.Filename, s.Rationale)
	}
	body.WriteString("\n<sub>Opened by PerspectiveGraph. Review before merging.</sub>\n")

	url, err := a.prOpener.OpenPR(r.Context(), action.OpenPRRequest{
		Slug:   slug,
		Branch: "perspectivegraph/fix-" + branchID(path.ID),
		Title:  "PerspectiveGraph: remediate path to " + path.Target().Name,
		Body:   body.String(),
		Files:  files,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "could not open PR: "+err.Error())
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record("remediation.pr", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"path": path.ID, "slug": slug, "url": url, "files": len(files),
	})
	writeJSON(w, http.StatusOK, map[string]any{"url": url, "files": len(files)})
}

func findPath(paths []analyzer.AttackPath, id string) (analyzer.AttackPath, bool) {
	for _, p := range paths {
		if p.ID == id {
			return p, true
		}
	}
	return analyzer.AttackPath{}, false
}

func repoSlugOf(p analyzer.AttackPath) string {
	for _, n := range p.Nodes {
		if s, _ := n.Properties[ontology.PropRepoSlug].(string); strings.Contains(s, "/") {
			return s
		}
	}
	return ""
}

// branchID keeps a path id to a git-ref-safe, bounded slug (the "/" prefix is
// added by the caller, so this only sanitizes the trailing segment).
func branchID(id string) string {
	out := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	s := string(out)
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
