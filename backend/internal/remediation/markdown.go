package remediation

import (
	"strings"
	"unicode"
)

// Hints, and the pull-request comment that carries them, are Markdown posted as the
// engine's word, and the names in them are the environment's: an EC2 Name tag is anyone's
// with ec2:CreateTags, a file path is whoever named the file. So a name is written as a
// value. It stays on one line, so it cannot start a line of its own (a heading saying the
// change was reviewed), and it sits in code it cannot close, set off by a run of backticks
// longer than any it holds, which CommonMark says no shorter run can end.

// CodeSpan renders s as one inline code span, whatever it contains: on one line, and
// delimited by a run of backticks longer than any inside it.
func CodeSpan(s string) string {
	s = OneLine(s)
	tick := strings.Repeat("`", LongestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return tick + s + tick
}

// OneLine collapses every run of whitespace in s, line breaks included, to one space,
// and drops control and format characters, which render as nothing to the reader.
func OneLine(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
				space = true
			}
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
			space = false
		}
	}
	return strings.TrimSpace(b.String())
}

// LongestRun is the length of the longest run of c in s: a code block fenced with a
// longer run of backticks cannot be closed by anything inside it.
func LongestRun(s string, c byte) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	return longest
}
