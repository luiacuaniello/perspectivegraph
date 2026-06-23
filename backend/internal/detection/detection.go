// Package detection turns an attack path into detection-as-code: Falco and
// Sigma rules that catch an attacker *exploiting* the path. Remediation cuts the
// path; detection watches it. PerspectiveGraph already ingests Falco at runtime,
// so this closes the offense→defense loop - the path says exactly which workload
// to instrument.
package detection

import (
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
id: perspectivegraph-%s
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
`, name, sanitize(pathID), name, target.Name, cveNote)

	return Detection{
		Kind:      "sigma",
		Title:     "Sigma: process anomaly on " + name,
		Filename:  "sigma-" + sanitize(name) + ".yml",
		Content:   content,
		Rationale: "A SIEM-portable companion detection for the same workload; deploy where you don't run Falco.",
	}
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
