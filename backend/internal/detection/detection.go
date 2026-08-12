// Package detection turns an attack path into detection-as-code: Falco and
// Sigma rules that catch an attacker *exploiting* the path. Remediation cuts the
// path; detection watches it. PerspectiveGraph already ingests Falco at runtime,
// so this closes the offense→defense loop - the path says exactly which workload
// to instrument.
package detection

import (
	"crypto/sha1" // #nosec G505 -- RFC 4122 mandates SHA-1 for UUIDv5; a rule identifier, not a security primitive
	"fmt"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Detection is one generated detection rule.
type Detection struct {
	Kind      string `json:"kind"` // "falco" | "sigma"
	Title     string `json:"title"`
	Filename  string `json:"filename"`
	Content   string `json:"content"` // the rule body (YAML)
	Rationale string `json:"rationale"`
}

// Generate emits detections for a path: a Falco + Sigma pair watching the
// exposed entry workload for post-exploitation activity, referencing the path's
// CVE and crown-jewel target so a responder has full context.
func Generate(p analyzer.AttackPath) []Detection {
	workload := firstOf(p, ontology.LabelContainer, ontology.LabelVirtualMachine)
	if workload == nil {
		return nil // nothing runtime to instrument on this path
	}
	target := p.Target()
	cve := firstOf(p, ontology.LabelCVE)
	cveNote := ""
	if cve != nil {
		cveNote = fmt.Sprintf(" (path traverses %s)", cve.Name)
	}

	return []Detection{
		falcoRule(*workload, target, cveNote, p.ID),
		sigmaRule(*workload, target, cveNote, p.ID),
	}
}

func falcoRule(w, target ontology.Node, cveNote, pathID string) Detection {
	name := w.Name
	ns := propStr(w, "k8s_ns")
	cond := fmt.Sprintf(`spawned_process and container and container.name = %q`, name)
	if ns != "" {
		cond = fmt.Sprintf(`spawned_process and k8s.ns.name = %q and container.name = %q`, ns, name)
	}
	content := fmt.Sprintf(`# PerspectiveGraph detection-as-code - watch the exposed workload %q on a
# reachable attack path to %q%s. Catches a shell/exec, the classic
# post-exploitation step. Tune the process list to the workload's baseline.
- rule: PerspectiveGraph attack-path activity in %s
  desc: Unexpected shell in %q, which sits on a reachable path to crown jewel %q.
  condition: >
    %s
    and proc.name in (shell_binaries, "nc", "ncat", "curl", "wget", "python", "perl")
  output: >
    Suspicious process in attack-path workload
    (user=%%user.name container=%%container.name image=%%container.image.repository
     cmd=%%proc.cmdline path=%s)
  priority: WARNING
  tags: [perspectivegraph, attack_path, mitre_execution, %s]
`, name, target.Name, cveNote, name, name, target.Name, cond, pathID, pathID)

	return Detection{
		Kind:      "falco",
		Title:     "Falco: post-exploitation in " + name,
		Filename:  "falco-" + sanitize(name) + ".yaml",
		Content:   content,
		Rationale: fmt.Sprintf("Detects an attacker landing on %q after exploiting this path; feed it back into the same Falco that confirms runtime activity.", name),
	}
}

func sigmaRule(w, target ontology.Node, cveNote, pathID string) Detection {
	name := w.Name
	content := fmt.Sprintf(`# PerspectiveGraph detection-as-code - host/EDR companion to the Falco rule.
title: Suspicious process in attack-path workload %s
id: %s
status: experimental
description: >
  Process execution in %q, a workload on a reachable attack path to crown jewel
  %q%s. Surfaces post-exploitation (shells, recon, egress tools).
logsource:
  category: process_creation
detection:
  selection_proc:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/nc'
      - '/ncat'
      - '/curl'
      - '/wget'
  condition: selection_proc
fields:
  - Image
  - CommandLine
  - ContainerName
level: high
tags:
  - perspectivegraph
  - attack.execution
  - attack.t1059
  - perspectivegraph.path.%s
`, name, sigmaID(pathID), name, target.Name, cveNote, sanitize(pathID))

	return Detection{
		Kind:      "sigma",
		Title:     "Sigma: process anomaly on " + name,
		Filename:  "sigma-" + sanitize(name) + ".yml",
		Content:   content,
		Rationale: "A SIEM-portable companion detection for the same workload; deploy where you don't run Falco.",
	}
}

// sigmaID turns a path id into the UUID the Sigma specification requires.
//
// Sigma defines `id` as a UUID and converters validate it, so the previous
// "perspectivegraph-ap-edge-alb-payments-admin-9ebc68f4" was self-describing but not
// loadable everywhere - and a rule a SIEM refuses is worse than one with an opaque
// identifier.
//
// Version 5 keeps both properties. It is a real UUID, and it is DERIVED from the path
// id, so the same route always yields the same rule id: re-issuing a rule updates it in
// place instead of accumulating copies. What the UUID costs in legibility the tag gives
// back - the readable path id moves into `tags:` (as the Falco rule already did), which
// is where an analyst correlates an alert to the route that predicted it.
func sigmaID(pathID string) string {
	return uuidV5(urlNamespace, "https://github.com/luiacuaniello/perspectivegraph/rules/"+pathID)
}

// RFC 4122's URL namespace. The standard one rather than a minted project UUID, so the
// derivation is reproducible by anyone: given the path id, the rule id can be recomputed
// with any UUID library, which is what makes it auditable rather than magic.
var urlNamespace = [16]byte{
	0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

func uuidV5(ns [16]byte, name string) string {
	// SHA-1 because RFC 4122 defines version 5 that way. This is a name, not a signature:
	// SHA-1's weakness to chosen-prefix collisions has no bearing on an identifier whose
	// input is our own path id.
	h := sha1.New() // #nosec G401 -- see the import: RFC 4122 mandates SHA-1 for UUIDv5
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// firstOf returns the first node on the path matching any of the labels.
func firstOf(p analyzer.AttackPath, labels ...ontology.Label) *ontology.Node {
	for i := range p.Nodes {
		for _, l := range labels {
			if p.Nodes[i].Label == l {
				return &p.Nodes[i]
			}
		}
	}
	return nil
}

func propStr(n ontology.Node, key string) string {
	s, _ := n.Properties[key].(string)
	return s
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
