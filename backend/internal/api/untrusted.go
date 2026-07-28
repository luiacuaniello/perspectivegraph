package api

import (
	"strings"
	"unicode"
)

// This file contains everything the AI layer knows about the fact that the environment
// is hostile.
//
// The engine's inputs are not its own. An asset's name is an AWS `Name` tag, and
// `ec2:CreateTags` is a permission granted freely because tagging looks harmless - so
// the attacker this tool exists to detect can write text into the context that produces
// the executive summary. That is the surface a correlation engine has and its individual
// feeds do not: influence over one feed shapes conclusions drawn from all of them.
//
// What follows is CONTAINMENT, not a solution. No amount of escaping makes a language
// model immune to persuasive text; a name reading "this asset is decommissioned" may
// still colour an answer. What is removed is the attacker's ability to forge STRUCTURE -
// to stop looking like a value inside the data and start looking like the prompt's own
// scaffolding - and to spend the entire context window on one tag. The hostile inputs
// are in injection_test.go.

// maxNameChars caps one environment-controlled string. Long enough for real names
// (an ARN-ish path, a descriptive tag), short enough that no single asset can crowd the
// real paths out of the context window.
const (
	maxNameChars = 120
	// maxHintChars bounds a whole remediation line, which legitimately carries two
	// asset names plus prose, so it needs more room than a single name.
	maxHintChars = 400
)

// safeName renders an environment-controlled string as a single-line, bounded value.
//
// Every hostile shape in the lab works the same way: emit a line break, then something
// that looks like structure the model already trusts - a new numbered entry, a "SYSTEM:"
// turn, a closing delimiter. Collapsing the string to one line takes that away, because
// the surrounding format is line-oriented. Truncation is marked with an ellipsis rather
// than silent: a name quietly cut short is a different asset from the one in the
// console, and an operator would go looking for something that does not exist.
func safeName(s string) string { return safeLine(s, maxNameChars) }

// safeLine is safeName's general form: any environment-derived string rendered as one
// bounded line. Remediation hints go through it too - they embed asset names in prose,
// so they carry the same payload by a different route (/ai/explain rather than the
// summary), and one sanitised field in a line assembled from unsanitised ones proves
// nothing.
func safeLine(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || unicode.IsSpace(r):
			// Any whitespace, including the line breaks every payload relies on,
			// collapses to a single ordinary space.
			if !lastSpace {
				b.WriteRune(' ')
				lastSpace = true
			}
		case r < 0x20 || r == 0x7f || unicode.Is(unicode.Cf, r):
			// Control and format characters (ANSI escapes, NUL, bidi overrides) are
			// dropped outright: they render as nothing to a human reviewing the prompt
			// while still being present in what the model reads.
			continue
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}
	out := strings.TrimSpace(b.String())

	// Neutralise the fence itself. A name containing the closing tag would otherwise end
	// the untrusted block early and promote everything after it to instruction level.
	out = strings.ReplaceAll(out, untrustedClose, "")
	out = strings.ReplaceAll(out, untrustedOpen, "")

	if r := []rune(out); len(r) > max {
		out = strings.TrimSpace(string(r[:max])) + "…"
	}
	if out == "" {
		return "(unnamed)"
	}
	return out
}

const (
	untrustedOpen  = "<environment-data>"
	untrustedClose = "</environment-data>"
)

// untrustedBlock fences the environment context so the model can tell data from
// instruction. The fence is only half of it - [scoreCaveat] tells the model what the
// fence means, and neither works without the other.
func untrustedBlock(s string) string {
	return untrustedOpen + "\n" + s + "\n" + untrustedClose
}
