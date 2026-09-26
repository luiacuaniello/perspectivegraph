package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
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
//
// It comments on the paths that count against the change - the merge gate's rule, see
// impact.Ledger - and says why: a route the change opened, or one it made likelier. A
// route that was there before the change is not its to answer for, and a comment on
// every one of them is the noise that teaches a team to stop reading.
type Commenter struct {
	p      poster
	allow  *RepoAllow     // where writes are permitted; nil denies everything
	judge  *impact.Ledger // nil: every route through the change counts
	mu     sync.Mutex
	posted map[string]string // dedupe key -> last body hash
}

// maxCommentPages bounds the marker search on pathological PRs (100 comments
// per page → 2,000 comments scanned at most).
const maxCommentPages = 20

func newCommenter(p poster, allow *RepoAllow) *Commenter {
	return &Commenter{p: p, allow: allow, posted: map[string]string{}}
}

func (c *Commenter) withJudge(l *impact.Ledger) *Commenter {
	c.judge = l
	return c
}

// permitted reports whether this comment may be posted at all. The slug comes from a
// node property, so it is attacker-influenceable input choosing a write destination -
// see repoguard.go. Dry-run is exempt because it makes no outbound call: the demo
// keeps printing what it would post without anyone having to configure an allowlist.
func (c *Commenter) permitted(slug string) bool {
	if !c.p.enabled() || c.allow.Permit(slug) {
		return true
	}
	slog.Warn("pr comment refused: repository not allowed",
		"forge", c.p.forge(), "slug", slug, "hint", "add it to REPO_ALLOWLIST")
	return false
}

func (c *Commenter) OnCriticalPaths(ctx context.Context, tenant string, paths []analyzer.AttackPath) {
	for _, p := range paths {
		for _, t := range prsOn(p) {
			if !c.permitted(t.slug) {
				continue
			}
			v, counts := c.verdict(tenant, t, p)
			if !counts {
				continue // there before this change: not its to answer for
			}
			ref := prRef{slug: t.slug, number: t.number}
			marker := fmt.Sprintf("<!-- perspectivegraph:attack-path:%s -->", p.ID)
			body := marker + "\n" + commentBody(p, v)
			if err := c.upsert(ctx, ref, p.ID, marker, body); err != nil {
				slog.Error("pr commenter failed", "forge", c.p.forge(), "slug", t.slug, "number", t.number, "path", p.ID, "err", err)
			}
		}
	}
}

// verdict judges a path against a pull request through the commits of it the path
// carries - a later push may have restamped some of its assets and not others. The
// strongest reason wins, so the comment does not flip between two on alternate passes.
func (c *Commenter) verdict(tenant string, t prOnPath, p analyzer.AttackPath) (impact.Verdict, bool) {
	var best impact.Verdict
	for _, sha := range t.shas {
		v := c.judge.Judge(tenant, t.slug, sha, p)
		if v.Counts && rank(v.Change) > rank(best.Change) {
			best = v
		}
	}
	return best, best.Counts
}

func rank(ch impact.Change) int {
	switch ch {
	case impact.Introduced:
		return 4
	case impact.Worsened:
		return 3
	case impact.Later:
		return 2
	case impact.Recorded:
		return 1
	}
	return 0
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

// prOnPath is a pull/merge request whose context a path carries, with the commits of it
// stamped on the path's nodes.
type prOnPath struct {
	slug   string
	number int
	shas   []string
}

// prsOn lists the distinct pull/merge requests a path carries - every one, not the
// first: a route through two changes is a question for each of them.
func prsOn(p analyzer.AttackPath) []prOnPath {
	var out []prOnPath
	at := map[prRef]int{}
	for _, n := range p.Nodes {
		s, _ := n.Properties[ontology.PropRepoSlug].(string)
		num := toInt(n.Properties[ontology.PropPRNumber])
		if num <= 0 || !ValidSlug(s) {
			continue
		}
		sha, _ := n.Properties[ontology.PropCommitSHA].(string)
		ref := prRef{slug: s, number: num}
		i, ok := at[ref]
		if !ok {
			i = len(out)
			at[ref] = i
			out = append(out, prOnPath{slug: s, number: num})
		}
		if !slices.Contains(out[i].shas, sha) {
			out[i].shas = append(out[i].shas, sha)
		}
	}
	return out
}

func commentBody(p analyzer.AttackPath, v impact.Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 🚨 PerspectiveGraph - reachable attack path detected\n\n")
	if p.RuntimeConfirmed {
		b.WriteString("> ⚡ **Actively exploited** - a runtime sensor (Falco) has fired on this path.\n\n")
	}
	fmt.Fprintf(&b, "This change sits on a **verified attack path** "+
		"(exploit likelihood **%.0f%%**) from an internet-exposed entry point "+
		"to a sensitive asset (`%s`).\n\n", p.Score*100, p.Target().Name)
	switch v.Change {
	case impact.Introduced:
		fmt.Fprintf(&b, "**This change opens it:** nothing led from `%s` to `%s` before it.\n\n",
			p.Source().Name, p.Target().Name)
	case impact.Worsened:
		fmt.Fprintf(&b, "**This change makes it likelier:** %.0f%% before it, %.0f%% now.\n\n",
			v.PreviousScore*100, p.Score*100)
	case impact.Later:
		b.WriteString("**This route appeared through this change's assets after it arrived**, with no other " +
			"pull request arriving on it at the time - the rest of a large report, or a change made outside " +
			"a pull request. It runs through this change, so it counts.\n\n")
	}

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
