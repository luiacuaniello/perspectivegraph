// Package dataclass ingests data-classification findings from a real classifier
// (AWS Macie, a DLP scan, or a tag-policy export) and marks the named asset as a
// crown jewel — authoritative evidence that it holds sensitive data, far stronger
// than guessing from the asset's name. The classification rides on the asset node
// (matched by stable id to the cloud/k8s feeds), and the normalizer turns a
// sensitive class (pii/phi/pci/…) into crown_jewel with a "classified:…" basis.
package dataclass

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// report is a list of classification findings, e.g. Macie's sensitive-data results.
type report struct {
	Source  string   `json:"source"` // default source label (e.g. "macie")
	Records []record `json:"records"`
}

type record struct {
	Asset  string `json:"asset"`  // the data store's name (must match the cloud/k8s feeds)
	Label  string `json:"label"`  // ontology label: Bucket (default) | Database
	Kind   string `json:"kind"`   // classification: pii | phi | pci | financial | secret | …
	Source string `json:"source"` // optional per-record source override
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "dataclass" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode dataclass report: %w", err)
	}

	var nodes []ontology.Node
	for _, rec := range rep.Records {
		asset := strings.TrimSpace(rec.Asset)
		kind := strings.ToLower(strings.TrimSpace(rec.Kind))
		if asset == "" || kind == "" {
			continue
		}
		label := ontology.LabelBucket
		if strings.EqualFold(rec.Label, string(ontology.LabelDatabase)) {
			label = ontology.LabelDatabase
		}
		src := firstNonEmpty(rec.Source, rep.Source, "classifier")
		nodes = append(nodes, ontology.Node{
			// Same id the cloud/k8s feed used → this merges onto the existing asset.
			ID:    ontology.NewID(label, asset),
			Label: label,
			Name:  asset,
			Properties: map[string]any{
				ontology.PropClassification:  kind,
				"classification_source":      src,
				ontology.PropCrownJewelBasis: "classified:" + src + ":" + kind,
			},
		})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("dataclass report has no usable records (need asset + kind)")
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
	}}, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
