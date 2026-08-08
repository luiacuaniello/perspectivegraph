// Package basimport maps a BAS or red-team report onto the engine's live attack paths.
//
// It lives here, rather than inside the CLI subcommand that calls it, because it decides
// which path a tester's verdict is recorded against - and those verdicts are the evidence
// the calibration reports are computed from. Resolve to the wrong path and the engine is
// graded on something the tester never tried; resolve to nothing and a real outcome is
// silently discarded. Neither is visible in the numbers afterwards, which is exactly why
// it belongs somewhere it can be tested.
package basimport

import "strings"

// PathInfo is the subset of a live attack path needed to match a finding to it.
type PathInfo struct {
	ID       string
	From     string // the entry point's name
	Target   string // the sensitive asset's name
	Priority float64
}

// Resolve maps a finding to a live path id.
//
// An explicit path id always wins - a tester who names the path has said which one they
// mean. Otherwise the match is on the target's name, optionally narrowed by the entry
// point, and among the candidates the HIGHEST-PRIORITY path wins.
//
// The comparison is a case-insensitive substring on purpose: a tester writes
// "account-admin" where the engine holds "account-admin (effective)", and demanding they
// match exactly would throw away real outcomes over a formatting difference.
//
// Reports false when nothing matches, so the caller can say so rather than record the
// verdict against an arbitrary path.
func Resolve(paths []PathInfo, pathID, target, from string) (string, bool) {
	if pathID != "" {
		return pathID, true
	}
	if target == "" {
		return "", false
	}
	best, bestPri := "", -1.0
	for _, p := range paths {
		if !containsFold(p.Target, target) {
			continue
		}
		if from != "" && !containsFold(p.From, from) {
			continue
		}
		if p.Priority > bestPri {
			best, bestPri = p.ID, p.Priority
		}
	}
	return best, best != ""
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
