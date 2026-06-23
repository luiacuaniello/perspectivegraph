// Package normalization consumes events off the bus, resolves asset identity
// across tools (so Trivy's "image:tag", an ECR image URI, and a K8s PodSpec
// collapse to one node), and upserts the result into the graph.
//
// Identity resolution here is two complementary things:
//
//   - Canonicalization - rewriting ids so the same real asset reported by
//     different tools converges (registry prefixes stripped from image refs,
//     plus a learned alias table).
//   - Relationship inference - synthesizing edges that no single tool reports
//     but the graph needs, e.g. linking a runtime/cloud Container to the Image
//     a scanner analyzed (Container --HOSTS--> Image) via its image reference.
package normalization

import (
	"context"
	"log/slog"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/scrub"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Normalizer is the bus handler that turns events into graph mutations, routing
// each event to its tenant's isolated store.
type Normalizer struct {
	manager *graph.Manager
	indexer search.Indexer
	intel   threatintel.Source
	scrub   bool
}

// New returns a Normalizer with secret scrubbing on by default - the safe posture
// for a tool that must not become a store of the credentials its scanners
// captured. Disable it with WithScrub(false).
func New(manager *graph.Manager) *Normalizer {
	return &Normalizer{manager: manager, indexer: search.Noop{}, intel: threatintel.Noop{}, scrub: true}
}

// WithIndexer attaches a full-text indexer; resolved nodes are indexed after
// they are written to the graph. Returns the normalizer for chaining.
func (n *Normalizer) WithIndexer(idx search.Indexer) *Normalizer {
	if idx != nil {
		n.indexer = idx
	}
	return n
}

// WithThreatIntel attaches a KEV/EPSS source; CVE nodes are enriched and their
// AFFECTS edges reweighted by observed exploitation likelihood. Returns the
// normalizer for chaining.
func (n *Normalizer) WithThreatIntel(src threatintel.Source) *Normalizer {
	if src != nil {
		n.intel = src
	}
	return n
}

// WithScrub toggles secret redaction at ingest (see internal/scrub). On by
// default; pass false only when you have a deliberate reason to persist raw
// scanner values. Returns the normalizer for chaining.
func (n *Normalizer) WithScrub(enabled bool) *Normalizer {
	n.scrub = enabled
	return n
}

// Handle is the broker consumer callback: it routes the event to its tenant's
// store and search index.
func (n *Normalizer) Handle(ctx context.Context, ev ontology.Event) error {
	ev = n.canonicalize(ev)
	ev = inferImageHosts(ev)
	ev = classifyCrownJewels(ev) // authoritative data classification (Macie/DLP/tag) first…
	ev = inferCrownJewels(ev)    // …then the weaker name heuristic fills any gaps
	n.enrichThreatIntel(ctx, &ev)
	if n.scrub {
		ev = scrubSensitive(ev) // last: redact secrets a scanner captured before they hit the store
	}

	tenant := graph.NormalizeTenant(ev.Tenant)
	store, err := n.manager.For(ctx, tenant)
	if err != nil {
		return err
	}
	if err := graph.ApplyEvent(ctx, store, ev); err != nil {
		return err
	}
	if n.indexer.Enabled() {
		if err := n.indexer.Index(ctx, tenant, ev.Nodes); err != nil {
			slog.Warn("full-text index failed (continuing)", "tenant", tenant, "err", err)
		}
	}
	return nil
}

// canonicalize rewrites node ids through image-ref normalization so duplicate
// assets converge before they hit the graph.
func (n *Normalizer) canonicalize(ev ontology.Event) ontology.Event {
	rewrite := map[string]string{}
	for i := range ev.Nodes {
		node := &ev.Nodes[i]
		canon := node.ID
		// Images: key on the registry-stripped repo:tag.
		if node.Label == ontology.LabelImage {
			if id := ontology.NewID(ontology.LabelImage, NormalizeImageRef(node.Name)); id != canon {
				canon = id
			}
		}
		if canon != node.ID {
			rewrite[node.ID] = canon
			node.ID = canon
		}
	}
	if len(rewrite) > 0 {
		apply := func(id string) string {
			if c, ok := rewrite[id]; ok {
				return c
			}
			return id
		}
		for i := range ev.Edges {
			ev.Edges[i].From = apply(ev.Edges[i].From)
			ev.Edges[i].To = apply(ev.Edges[i].To)
		}
	}
	return ev
}

// enrichThreatIntel looks up KEV/EPSS for the event's CVE nodes, stamps the
// intel as node properties, and reweights each AFFECTS edge into a CVE by its
// observed exploitation likelihood (KEV/EPSS beat a severity guess). A no-op
// when the source is disabled or the event carries no CVEs.
func (n *Normalizer) enrichThreatIntel(ctx context.Context, ev *ontology.Event) {
	if !n.intel.Enabled() {
		return
	}
	var cves []string
	for _, node := range ev.Nodes {
		if node.Label == ontology.LabelCVE && node.Name != "" {
			cves = append(cves, node.Name)
		}
	}
	if len(cves) == 0 {
		return
	}
	intel := n.intel.Scores(ctx, cves)
	if len(intel) == 0 {
		return
	}

	// id -> intel, so we can reweight edges by their CVE endpoint.
	byID := map[string]threatintel.Intel{}
	for i := range ev.Nodes {
		node := &ev.Nodes[i]
		in, ok := intel[node.Name]
		if node.Label != ontology.LabelCVE || !ok {
			continue
		}
		if node.Properties == nil {
			node.Properties = map[string]any{}
		}
		node.Properties[ontology.PropKEV] = in.KEV
		node.Properties[ontology.PropEPSS] = in.EPSS
		node.Properties[ontology.PropEPSSPercentile] = in.Percentile
		byID[node.ID] = in
	}
	for i := range ev.Edges {
		e := &ev.Edges[i]
		if in, ok := byID[e.To]; ok && e.Type == ontology.EdgeAffects {
			e.ExploitProbability = in.EdgeProbability(e.ExploitProbability)
			// Record that this weight rests on observed intel (kev/epss), not a
			// severity guess, so the score can show its provenance.
			if basis := in.Basis(); basis != "" {
				if e.Properties == nil {
					e.Properties = map[string]any{}
				}
				e.Properties[ontology.PropWeightBasis] = basis
			}
		}
	}
}

// inferImageHosts links any Container/VM that declares the image it runs to the
// corresponding Image node, so a finding on the image becomes reachable from
// the workload. The Image node is stubbed in case no scanner reported it yet.
func inferImageHosts(ev ontology.Event) ontology.Event {
	for _, node := range ev.Nodes {
		if node.Label != ontology.LabelContainer && node.Label != ontology.LabelVirtualMachine {
			continue
		}
		ref, _ := node.Properties[ontology.PropImageRef].(string)
		if ref == "" {
			continue
		}
		key, method, confidence := imageMatch(ref)
		imgID := ontology.NewID(ontology.LabelImage, key)
		if !hasNode(ev.Nodes, imgID) {
			// Carry the join provenance so the analyst can see this image identity
			// was *inferred* from a ref - and how confidently - not asserted.
			ev.Nodes = append(ev.Nodes, ontology.Node{
				ID:    imgID,
				Label: ontology.LabelImage,
				Name:  key,
				Properties: map[string]any{
					ontology.PropResolutionMethod:     method,
					ontology.PropResolutionConfidence: confidence,
					ontology.PropResolutionAlias:      ref,
				},
			})
		}
		if !hasEdge(ev.Edges, ontology.EdgeHosts, node.ID, imgID) {
			ev.Edges = append(ev.Edges, ontology.Edge{
				Type: ontology.EdgeHosts,
				From: node.ID,
				To:   imgID,
				// A weaker join lowers the edge probability too, so a path resting
				// on a shaky correlation scores lower than one on a hard identity.
				ExploitProbability: 0.6 + 0.35*confidence,
				Properties: map[string]any{
					ontology.PropResolutionMethod:     method,
					ontology.PropResolutionConfidence: confidence,
				},
			})
		}
	}
	return ev
}

// crownJewelSignals are name fragments that strongly imply a data store holds
// something worth stealing. Deliberately conservative - only data stores (which
// are exfiltration targets by nature) are inferred, so a guessed jewel is a rare,
// auditable event, not noise.
var crownJewelSignals = []string{
	"pii", "customer", "secret", "credential", "ssn", "payment", "financial",
	"patient", "billing", "sensitive", "cardholder", "private-key",
}

// scrubSensitive redacts secret-looking values out of node and edge properties
// before they reach the graph, so the attack map never persists a raw credential
// a scanner happened to capture (see internal/scrub). Identity fields (id, name)
// are deliberately left intact - they are how nodes dedup and join - so only
// string property VALUES are inspected. A node that had a value redacted is
// stamped PropSecretsScrubbed so the masking is auditable.
func scrubSensitive(ev ontology.Event) ontology.Event {
	for i := range ev.Nodes {
		if scrubProps(ev.Nodes[i].Properties) {
			if ev.Nodes[i].Properties == nil {
				ev.Nodes[i].Properties = map[string]any{}
			}
			ev.Nodes[i].Properties[ontology.PropSecretsScrubbed] = true
		}
	}
	for i := range ev.Edges {
		scrubProps(ev.Edges[i].Properties)
	}
	return ev
}

// scrubProps redacts secret-looking string values in place and reports whether
// anything was masked.
func scrubProps(props map[string]any) bool {
	hit := false
	for k, v := range props {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if red, _, found := scrub.Redact(s); found {
			props[k] = red
			hit = true
		}
	}
	return hit
}

// sensitiveClassifications are data-classification values that make an asset a
// crown jewel on their own - authoritative evidence from a real classifier
// (Macie/DLP/tag policy), not a name guess.
var sensitiveClassifications = map[string]bool{
	"pii": true, "phi": true, "pci": true, "financial": true, "cardholder": true,
	"secret": true, "credential": true, "sensitive": true, "confidential": true,
	"restricted": true,
}

// classifyCrownJewels marks any node carrying a sensitive `classification`
// property as a crown jewel with basis "classified:<value>" - authoritative, so
// it runs before the name heuristic and an explicit owner tag still wins.
func classifyCrownJewels(ev ontology.Event) ontology.Event {
	for i := range ev.Nodes {
		node := &ev.Nodes[i]
		cls, _ := node.Properties[ontology.PropClassification].(string)
		cls = strings.ToLower(strings.TrimSpace(cls))
		if cls == "" || !sensitiveClassifications[cls] {
			continue
		}
		if _, tagged := node.Properties[ontology.PropCrownJewel]; tagged {
			continue // never override an explicit owner decision
		}
		if node.Properties == nil {
			node.Properties = map[string]any{}
		}
		node.Properties[ontology.PropCrownJewel] = true
		// Keep a richer basis the source already set (e.g. "classified:macie:pii").
		if _, ok := node.Properties[ontology.PropCrownJewelBasis]; !ok {
			node.Properties[ontology.PropCrownJewelBasis] = "classified:" + cls
		}
	}
	return ev
}

// inferCrownJewels reduces reliance on perfect hand-tagging: an untagged Database
// or Bucket whose name strongly implies sensitive data is marked a crown jewel,
// with crown_jewel_basis="inferred:<signal>" so the guess is transparent and
// auditable. An explicit tag (crown_jewel already present) always wins.
func inferCrownJewels(ev ontology.Event) ontology.Event {
	for i := range ev.Nodes {
		node := &ev.Nodes[i]
		if node.Label != ontology.LabelDatabase && node.Label != ontology.LabelBucket {
			continue
		}
		if _, tagged := node.Properties[ontology.PropCrownJewel]; tagged {
			continue // never override an explicit owner decision
		}
		hay := strings.ToLower(node.Name + " " + node.ID)
		for _, sig := range crownJewelSignals {
			if strings.Contains(hay, sig) {
				if node.Properties == nil {
					node.Properties = map[string]any{}
				}
				node.Properties[ontology.PropCrownJewel] = true
				node.Properties[ontology.PropCrownJewelBasis] = "inferred:" + sig
				break
			}
		}
	}
	return ev
}

// imageMatch maps an image ref to its canonical node key and how confident the
// container→image join is: a digest pin is an exact identity, a tagged ref is
// strong, a bare name (no tag/digest) is weak and worth verifying.
func imageMatch(ref string) (key, method string, confidence float64) {
	key = NormalizeImageRef(ref)
	switch {
	case strings.Contains(ref, "@sha256:") || strings.Contains(ref, "@sha512:"):
		return key, "digest", 1.0
	case strings.Contains(key, ":"):
		return key, "tag", 0.85
	default:
		return key, "name", 0.6
	}
}

// NormalizeImageRef strips a registry host prefix (and Docker Hub's implicit
// "library/" namespace) so equivalent image references resolve to the same node:
//
//	123.dkr.ecr.us-east-1.amazonaws.com/payments-api:1.4.2  ->  payments-api:1.4.2
//	docker.io/library/nginx:1.25                            ->  nginx:1.25
//	library/nginx:1.25                                      ->  nginx:1.25
//	nginx:1.25                                              ->  nginx:1.25 (unchanged)
//	payments-api:1.4.2                                      ->  payments-api:1.4.2 (unchanged)
func NormalizeImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if host, rest, ok := strings.Cut(ref, "/"); ok &&
		(strings.Contains(host, ".") || strings.Contains(host, ":") || host == "localhost") {
		ref = rest
	}
	// Docker Hub official images: the "library/" namespace and the bare name a
	// scanner reports are the same image.
	if rest, ok := strings.CutPrefix(ref, "library/"); ok && !strings.Contains(rest, "/") {
		ref = rest
	}
	return ref
}

func hasNode(nodes []ontology.Node, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func hasEdge(edges []ontology.Edge, t ontology.EdgeType, from, to string) bool {
	for _, e := range edges {
		if e.Type == t && e.From == from && e.To == to {
			return true
		}
	}
	return false
}
