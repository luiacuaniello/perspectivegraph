// Package labrecord carries the latest result of each lab that puts the engine's rules to a
// real AWS account with AWS as the referee: what S3 says of a bucket policy, what a
// stranger's request gets, what IAM's policy simulator or Kubernetes' authorizer allows an
// identity to do. The lab scripts write one record per run into records/, and the records
// are built into the binary, so every instance shows how the rules of its own version were
// checked. They are evidence about the engine, not about the estate it reads.
//
// The checks settle facts a route's steps rest on - is this bucket open, can this role
// escalate, does this service account get that role - not whether a whole route is
// exploitable end to end, which needs real exploitation and is the calibration's question.
package labrecord

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed records
var files embed.FS

// Verdicts a check can carry.
const (
	Agree     = "agree"     // the engine says what AWS says
	Disagree  = "disagree"  // a false positive or a miss
	Unsettled = "unsettled" // AWS gave no answer that settles it
)

// Check is one question put to AWS and to the engine.
type Check struct {
	Case     string `json:"case"`     // the resource or principal, as the lab names it
	Question string `json:"question"` // what was asked, in a sentence
	Referee  string `json:"referee"`  // where AWS's answer came from
	AWS      string `json:"aws"`      // AWS's answer
	Engine   string `json:"engine"`   // the engine's answer
	Verdict  string `json:"verdict"`  // agree | disagree | unsettled
	Note     string `json:"note,omitempty"`
}

// Run is one lab's latest run.
type Run struct {
	Lab     string    `json:"lab"`     // the script's name
	Title   string    `json:"title"`   // what the lab checks
	Command string    `json:"command"` // how to run it again
	Region  string    `json:"region"`
	Engine  string    `json:"engine"` // the engine version the run was made with
	RanAt   time.Time `json:"ran_at"`
	Cost    string    `json:"cost"`
	Checks  []Check   `json:"checks"`
}

// Count is how many of the run's checks carry the verdict.
func (r Run) Count(verdict string) int {
	n := 0
	for _, c := range r.Checks {
		if c.Verdict == verdict {
			n++
		}
	}
	return n
}

var (
	once    sync.Once
	loaded  []Run
	errLoad error
)

// All returns every record built into the binary, newest run first. They are read once:
// they cannot change while the binary runs.
func All() ([]Run, error) {
	once.Do(func() { loaded, errLoad = load(files, "records") })
	return loaded, errLoad
}

// accountID is any twelve-digit number - the shape of an AWS account ID, which a record
// must never publish. Lab names and versions never contain one.
var accountID = regexp.MustCompile(`(^|[^0-9])[0-9]{12}([^0-9]|$)`)

func load(fsys fs.FS, dir string) ([]Run, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var runs []Run
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if accountID.Match(raw) {
			return nil, fmt.Errorf("lab record %s carries a twelve-digit number, the shape of an AWS account ID: records are published", e.Name())
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var r Run
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("lab record %s: %w", e.Name(), err)
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("lab record %s: %w", e.Name(), err)
		}
		runs = append(runs, r)
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].RanAt.After(runs[j].RanAt) })
	return runs, nil
}

func (r Run) validate() error {
	switch {
	case strings.TrimSpace(r.Lab) == "" || strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Command) == "":
		return fmt.Errorf("lab, title and command are required")
	case r.RanAt.IsZero():
		return fmt.Errorf("ran_at is required")
	case len(r.Checks) == 0:
		return fmt.Errorf("a run without checks checked nothing")
	}
	for i, c := range r.Checks {
		if c.Case == "" || c.Question == "" || c.Referee == "" {
			return fmt.Errorf("check %d: case, question and referee are required", i)
		}
		switch c.Verdict {
		case Agree, Disagree, Unsettled:
		default:
			return fmt.Errorf("check %d (%s): verdict %q is none of agree, disagree, unsettled", i, c.Case, c.Verdict)
		}
	}
	return nil
}
