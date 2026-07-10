package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	remediationpkg "github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// prRef identifies a pull/merge request to comment on. slug is "owner/repo"
// (GitHub) or "group/project" (GitLab); number is the PR or MR number.
type prRef struct {
	slug   string
	number int
}

// poster abstracts the forge-specific REST calls. The shared Commenter handles
// rendering, deduplication, and upsert; each forge only implements find/create/
// update against its own API.
type poster interface {
	forge() string
	enabled() bool // false → dry-run (log instead of call)
	find(ctx context.Context, ref prRef, marker string) (commentID string, err error)
	create(ctx context.Context, ref prRef, body string) error
	update(ctx context.Context, ref prRef, commentID, body string) error
}

// Commenter posts (or updates) a comment on the PR/MR that introduced a finding
// sitting on a critical attack path. It satisfies analyzer.Sink.
//
// The analyzer fires every few seconds, so the commenter is idempotent on two
// levels: an in-memory body hash skips the API when nothing changed, and a
// hidden marker lets it update the existing comment instead of posting anew
// (which survives restarts).
type Commenter struct {
	p      poster
	mu     sync.Mutex
	posted map[string]string // dedupe key -> last body hash
}

// maxCommentPages bounds the marker search on pathological PRs (100 comments
// per page → 2,000 comments scanned at most).
const maxCommentPages = 20

func newCommenter(p poster) *Commenter {
	return &Commenter{p: p, posted: map[string]string{}}
}

func (c *Commenter) OnCriticalPaths(ctx context.Context, paths []analyzer.AttackPath) {
	for _, p := range paths {
		slug, num, ok := prTarget(p)
		if !ok {
			continue // no PR/MR context on this path
		}
		ref := prRef{slug: slug, number: num}
		marker := fmt.Sprintf("<!-- perspectivegraph:attack-path:%s -->", p.ID)
		body := marker + "\n" + commentBody(p)
		if err := c.upsert(ctx, ref, p.ID, marker, body); err != nil {
			slog.Error("pr commenter failed", "forge", c.p.forge(), "slug", slug, "number", num, "path", p.ID, "err", err)
		}
	}
}

func (c *Commenter) upsert(ctx context.Context, ref prRef, pathID, marker, body string) error {
	key := fmt.Sprintf("%s:%s#%d#%s", c.p.forge(), ref.slug, ref.number, pathID)
	h := hashString(body)

	c.mu.Lock()
	unchanged := c.posted[key] == h
	c.mu.Unlock()
	if unchanged {
		return nil
	}

	if !c.p.enabled() {
		slog.Info("pr commenter (dry-run)", "forge", c.p.forge(), "slug", ref.slug, "number", ref.number, "path", pathID)
		fmt.Printf("\n--- would comment on %s %s#%d ---\n%s\n", c.p.forge(), ref.slug, ref.number, body)
		c.remember(key, h)
		return nil
	}

	id, err := c.p.find(ctx, ref, marker)
	if err != nil {
		return err
	}
	if id != "" {
		if err := c.p.update(ctx, ref, id, body); err != nil {
			return err
		}
		slog.Info("updated PR comment", "forge", c.p.forge(), "slug", ref.slug, "number", ref.number)
	} else {
		if err := c.p.create(ctx, ref, body); err != nil {
			return err
		}
		slog.Info("created PR comment", "forge", c.p.forge(), "slug", ref.slug, "number", ref.number)
	}
	c.remember(key, h)
	return nil
}

func (c *Commenter) remember(key, hash string) {
	c.mu.Lock()
	c.posted[key] = hash
	c.mu.Unlock()
}

// ── comment rendering (forge-agnostic) ──────────────────────────────

// prTarget finds the first node on the path carrying PR/MR context and returns
// the repo slug and PR/MR number to comment on.
func prTarget(p analyzer.AttackPath) (slug string, number int, ok bool) {
	for _, n := range p.Nodes {
		s, _ := n.Properties[ontology.PropRepoSlug].(string)
		num := toInt(n.Properties[ontology.PropPRNumber])
		if s != "" && num > 0 && strings.Contains(s, "/") {
			return s, num, true
		}
	}
	return "", 0, false
}

func commentBody(p analyzer.AttackPath) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 🚨 PerspectiveGraph - reachable attack path detected\n\n")
	if p.RuntimeConfirmed {
		b.WriteString("> ⚡ **Actively exploited** - a runtime sensor (Falco) has fired on this path.\n\n")
	}
	fmt.Fprintf(&b, "This change sits on a **verified attack path** "+
		"(exploit likelihood **%.0f%%**) from an internet-exposed entry point "+
		"to a sensitive asset (`%s`).\n\n", p.Score*100, p.Target().Name)

	b.WriteString("**Path**\n```\n")
	b.WriteString(strings.TrimLeft(RenderPath(p), "\n"))
	b.WriteString("```\n\n")

	if fixes := remediationpkg.Hints(p); len(fixes) > 0 {
		b.WriteString("**Suggested remediation**\n")
		for _, f := range fixes {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "<sub>Posted by PerspectiveGraph · path `%s`. Cut any one edge on the path "+
		"to break it - you don't have to fix every finding.</sub>\n", p.ID)
	return b.String()
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// hashString is a non-cryptographic content fingerprint used only to skip
// re-posting an unchanged PR comment (in-memory equality). SHA-256 (over SHA-1)
// keeps SAST/due-diligence scanners quiet, at no functional cost.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// requestJSON marshals in (when set) and delegates to the shared httpx helper.
func requestJSON(ctx context.Context, client *http.Client, method, url string, headers map[string]string, in, out any) error {
	var body []byte
	contentType := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, contentType = b, "application/json"
	}
	return httpx.Do(ctx, client, method, url, headers, contentType, body, out)
}
