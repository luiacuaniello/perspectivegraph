package action

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A path's names come from the environment - an EC2 Name tag is anyone's with
// ec2:CreateTags - and the comment is posted on the pull request as the engine's word. A
// name used to go into it as it came: a run of backticks closed the code block the path is
// drawn in or the code span a name sits in, and a line break started a line of its own,
// so the comment could carry a heading that says the change was reviewed. A hostile name
// now leaves the comment with the lines, the code block and the code spans a plain one
// does.
func TestTheCommentCannotBeShapedByAnAssetName(t *testing.T) {
	hostile := map[string]string{
		"fence":       "web\n```\n## ✅ Reviewed - safe to merge\n```\n",
		"long fence":  "web\n`````\n## ✅ Reviewed - safe to merge\n`````\n",
		"tilde fence": "web\n~~~\n## ✅ Reviewed - safe to merge\n~~~\n",
		"code span":   "web` **✅ Reviewed - safe to merge** `",
		"line break":  "web\n\n## ✅ Reviewed - safe to merge",
		"crlf":        "web\r\n\r\n## ✅ Reviewed - safe to merge",
	}
	want := commentShape(commentFor("web"))
	for name, h := range hostile {
		t.Run(name, func(t *testing.T) {
			body := commentFor(h)
			if got := commentShape(body); got != want {
				t.Errorf("the name changed the comment's shape:\n%s\nwant:\n%s\n\ncomment:\n%s", got, want, body)
			}
		})
	}
}

// commentFor is the comment for a route that a change opens, from an entry point to a
// public role, both named name - the role so the remediation hint carries the name too.
func commentFor(name string) string {
	p := analyzer.AttackPath{ID: "ap-1", Score: 0.9,
		Nodes: []ontology.Node{
			{ID: "a", Label: ontology.LabelVirtualMachine, Name: name,
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "b", Label: ontology.LabelIAMRole, Name: name,
				Properties: map[string]any{ontology.PropCrownJewel: true, ontology.PropPublicAccess: true}},
		},
		Steps: []analyzer.Step{{EdgeType: ontology.EdgeAssumes, From: "a", To: "b", Probability: 0.9}},
	}
	return commentBody(p, impact.Verdict{Change: impact.Introduced})
}

// commentShape describes how Markdown reads a comment: per line, whether it opens or
// closes a fenced code block, sits inside one, or is prose with so many code spans.
func commentShape(body string) string {
	var out []string
	fence := ""
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		run := leadingRun(trimmed)
		switch {
		case fence == "" && len(run) >= 3:
			fence = run
			out = append(out, "open")
		case fence != "" && run != "" && run[0] == fence[0] && len(run) >= len(fence) &&
			strings.TrimSpace(trimmed[len(run):]) == "":
			fence = ""
			out = append(out, "close")
		case fence != "":
			out = append(out, "code")
		case strings.TrimSpace(line) == "":
			out = append(out, "")
		default:
			out = append(out, "prose "+strings.Repeat("c", codeSpans(line))+" "+blockMarker(line))
		}
	}
	return strings.Join(out, "\n")
}

// leadingRun is the run of backticks or tildes a line starts with.
func leadingRun(s string) string {
	if s == "" || (s[0] != '`' && s[0] != '~') {
		return ""
	}
	i := 0
	for i < len(s) && s[i] == s[0] {
		i++
	}
	return s[:i]
}

// codeSpans counts a line's code spans the way CommonMark finds them: a run of n
// backticks opens one, and only the next run of exactly n closes it.
func codeSpans(line string) int {
	n := 0
	for i := 0; i < len(line); {
		if line[i] != '`' {
			i++
			continue
		}
		j := i
		for j < len(line) && line[j] == '`' {
			j++
		}
		open := j - i
		closed := false
		for k := j; k < len(line); {
			if line[k] != '`' {
				k++
				continue
			}
			m := k
			for m < len(line) && line[m] == '`' {
				m++
			}
			if m-k == open {
				n++
				i, closed = m, true
				break
			}
			k = m
		}
		if !closed {
			i = j
		}
	}
	return n
}

// blockMarker is what a prose line starts as: a heading, a list item, a quote or text.
func blockMarker(line string) string {
	switch t := strings.TrimLeft(line, " "); {
	case strings.HasPrefix(t, "#"):
		return "heading"
	case strings.HasPrefix(t, "- "):
		return "item"
	case strings.HasPrefix(t, ">"):
		return "quote"
	default:
		return "text"
	}
}
