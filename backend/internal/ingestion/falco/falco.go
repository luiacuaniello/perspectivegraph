// Package falco converts Falco runtime alerts into ontology events.
//
// Falco watches kernel syscalls (via eBPF) and fires when a container does
// something suspicious at runtime - spawning a shell, opening an unexpected
// socket, writing to a sensitive path. PerspectiveGraph turns each alert into a
// runtime annotation on the affected Container node (runtime_alert=true). The
// analyzer then flags any attack path that traverses such a node as *actively
// confirmed* rather than merely theoretical, which is what should jump the
// queue for a responder.
//
// Input may be a single Falco JSON alert, a JSON array, or newline-delimited
// JSON (as emitted by `falco -o json_output=true` or falcosidekick).
package falco

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type alert struct {
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Output       string         `json:"output"`
	Time         string         `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "falco" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	alerts, err := decode(r)
	if err != nil {
		return nil, err
	}

	// One node per affected container; keep the highest-priority alert.
	containers := map[string]ontology.Node{}
	for _, a := range alerts {
		name := fieldStr(a.OutputFields, "container.name")
		if name == "" {
			name = fieldStr(a.OutputFields, "container.id")
		}
		if name == "" {
			continue // not a container-scoped alert
		}
		id := ontology.NewID(ontology.LabelContainer, name)

		incoming := ontology.Node{
			ID:    id,
			Label: ontology.LabelContainer,
			Name:  name,
			Properties: map[string]any{
				ontology.PropRuntimeAlert:    true,
				ontology.PropRuntimeRule:     a.Rule,
				ontology.PropRuntimePriority: a.Priority,
				"runtime_output":             a.Output,
				"k8s_pod":                    fieldStr(a.OutputFields, "k8s.pod.name"),
				"k8s_ns":                     fieldStr(a.OutputFields, "k8s.ns.name"),
				"proc_cmdline":               fieldStr(a.OutputFields, "proc.cmdline"),
			},
		}
		if ref := imageRef(a.OutputFields); ref != "" {
			incoming.Properties[ontology.PropImageRef] = ref // lets the resolver link to the scanned image
		}
		if cur, ok := containers[id]; !ok || severityRank(a.Priority) > severityRank(cur.Properties[ontology.PropRuntimePriority]) {
			containers[id] = incoming
		}
	}

	nodes := make([]ontology.Node, 0, len(containers))
	for _, n := range containers {
		nodes = append(nodes, n)
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRuntime,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
	}}, nil
}

// decode accepts a single alert (compact or pretty-printed), a JSON array, or
// NDJSON / any concatenation of JSON objects.
func decode(r io.Reader) ([]alert, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var arr []alert
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("decode falco array: %w", err)
		}
		return arr, nil
	}

	// A streaming decoder reads consecutive JSON objects wherever the
	// boundaries fall - unlike line-splitting, which broke on pretty-printed
	// single alerts spanning multiple lines.
	var out []alert
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var a alert
		if err := dec.Decode(&a); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode falco alert: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// imageRef assembles the container image reference from Falco's image fields.
func imageRef(f map[string]any) string {
	if full := fieldStr(f, "container.image"); full != "" {
		return full
	}
	repo := fieldStr(f, "container.image.repository")
	if repo == "" {
		return ""
	}
	if tag := fieldStr(f, "container.image.tag"); tag != "" {
		return repo + ":" + tag
	}
	return repo
}

func fieldStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// severityRank orders Falco priorities so we keep the most urgent alert.
func severityRank(p any) int {
	switch strings.ToLower(fmt.Sprint(p)) {
	case "emergency":
		return 7
	case "alert":
		return 6
	case "critical":
		return 5
	case "error":
		return 4
	case "warning":
		return 3
	case "notice":
		return 2
	case "informational", "info":
		return 1
	default:
		return 0
	}
}
