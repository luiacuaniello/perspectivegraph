// Package custodian converts a Cloud Custodian export into ontology events.
//
// Custodian runs a set of policies, each emitting a resources.json (the cloud
// resources that matched). This collector consumes a small bundle that groups
// those per-policy results together with their resource type:
//
//	{
//	  "provider": "aws",
//	  "policies": [
//	    {"policy": "...", "resource": "aws.elbv2", "resources": [ {...}, ... ]},
//	    ...
//	  ]
//	}
//
// Each resource dict is mapped onto an infrastructure/identity node, and the
// few relationship fields Custodian/AWS expose (load-balancer targets, instance
// profiles, accessible data stores) become edges. This is what lets cloud
// context produce attack paths like:
//
//	internet ELB --ROUTES_TO--> public EC2 --ASSUMES--> admin role --HAS_PERMISSION--> PII bucket
package custodian

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aegisgraph/aegisgraph/internal/ingestion"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

type bundle struct {
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
	Policies  []struct {
		Policy    string           `json:"policy"`
		Resource  string           `json:"resource"` // e.g. "aws.ec2", "aws.iam-role"
		Resources []map[string]any `json:"resources"`
	} `json:"policies"`
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "custodian" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode custodian bundle: %w", err)
	}

	g := &builder{nodes: map[string]ontology.Node{}}
	for _, pol := range b.Policies {
		for _, res := range pol.Resources {
			switch strings.ToLower(pol.Resource) {
			case "aws.ec2", "ec2", "vm":
				g.ec2(res)
			case "aws.iam-role", "iam-role", "iam":
				g.iamRole(res, pol.Policy)
			case "aws.s3", "s3", "bucket":
				g.bucket(res)
			case "aws.rds", "rds", "database":
				g.database(res)
			case "aws.elb", "aws.elbv2", "elb", "loadbalancer":
				g.loadBalancer(res)
			}
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes:      g.nodeSlice(),
		Edges:      g.edges,
	}}, nil
}

// builder accumulates nodes (deduped, stubs upgraded) and edges.
type builder struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
}

func (b *builder) upsert(n ontology.Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		// Merge: keep existing props, overlay new, prefer a real name.
		for k, v := range n.Properties {
			if existing.Properties == nil {
				existing.Properties = map[string]any{}
			}
			existing.Properties[k] = v
		}
		if n.Name != "" {
			existing.Name = n.Name
		}
		b.nodes[n.ID] = existing
		return
	}
	b.nodes[n.ID] = n
}

func (b *builder) stub(label ontology.Label, name string) string {
	id := ontology.NewID(label, name)
	if _, ok := b.nodes[id]; !ok {
		b.nodes[id] = ontology.Node{ID: id, Label: label, Name: name}
	}
	return id
}

func (b *builder) edge(t ontology.EdgeType, from, to string, p float64) {
	b.edges = append(b.edges, ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p})
}

func (b *builder) nodeSlice() []ontology.Node {
	out := make([]ontology.Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		out = append(out, n)
	}
	return out
}

func (b *builder) ec2(r map[string]any) {
	id := str(r["InstanceId"])
	if id == "" {
		return
	}
	nodeID := ontology.NewID(ontology.LabelVirtualMachine, id)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if ip := str(r["PublicIpAddress"]); ip != "" {
		props[ontology.PropInternetExposed] = true
		props["public_ip"] = ip
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelVirtualMachine, Name: name(r, id), Properties: props})

	if role := instanceProfile(r); role != "" {
		roleID := b.stub(ontology.LabelIAMRole, role)
		b.edge(ontology.EdgeAssumes, nodeID, roleID, 0.8)
	}
}

func (b *builder) iamRole(r map[string]any, policy string) {
	roleName := str(r["RoleName"])
	if roleName == "" {
		return
	}
	nodeID := ontology.NewID(ontology.LabelIAMRole, roleName)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if boolish(r["AdminAccess"]) || strings.Contains(strings.ToLower(policy), "admin") {
		props[ontology.PropCrownJewel] = true
		props["admin"] = true
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelIAMRole, Name: roleName, Properties: props})

	// "CanAccess": [{"type":"bucket","name":"customers-pii"}, ...]
	for _, raw := range slice(r["CanAccess"]) {
		acc, _ := raw.(map[string]any)
		target := b.dataStore(str(acc["type"]), str(acc["name"]))
		if target != "" {
			b.edge(ontology.EdgeHasPermission, nodeID, target, 0.7)
		}
	}
}

func (b *builder) bucket(r map[string]any) {
	name := str(r["Name"])
	if name == "" {
		return
	}
	props := map[string]any{}
	if boolish(r["Public"]) {
		props[ontology.PropInternetExposed] = true
	}
	if boolish(r["Sensitive"]) || boolish(r["PII"]) {
		props[ontology.PropCrownJewel] = true
	}
	b.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelBucket, name), Label: ontology.LabelBucket, Name: name, Properties: props})
}

func (b *builder) database(r map[string]any) {
	id := first(str(r["DBInstanceIdentifier"]), str(r["Name"]))
	if id == "" {
		return
	}
	props := map[string]any{}
	if boolish(r["Sensitive"]) || boolish(r["PII"]) {
		props[ontology.PropCrownJewel] = true
	}
	if boolish(r["PubliclyAccessible"]) {
		props[ontology.PropInternetExposed] = true
	}
	b.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelDatabase, id), Label: ontology.LabelDatabase, Name: id, Properties: props})
}

func (b *builder) loadBalancer(r map[string]any) {
	name := first(str(r["LoadBalancerName"]), str(r["Name"]))
	if name == "" {
		return
	}
	nodeID := ontology.NewID(ontology.LabelLoadBalancer, name)
	props := map[string]any{}
	if strings.EqualFold(str(r["Scheme"]), "internet-facing") {
		props[ontology.PropInternetExposed] = true
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelLoadBalancer, Name: name, Properties: props})

	for _, t := range slice(r["Targets"]) {
		if inst := str(t); inst != "" {
			vmID := b.stub(ontology.LabelVirtualMachine, inst)
			b.edge(ontology.EdgeRoutesTo, nodeID, vmID, 0.9)
		}
	}
}

// dataStore returns the canonical id for a bucket/database reference.
func (b *builder) dataStore(kind, name string) string {
	if name == "" {
		return ""
	}
	switch strings.ToLower(kind) {
	case "bucket", "s3":
		return b.stub(ontology.LabelBucket, name)
	case "database", "db", "rds":
		return b.stub(ontology.LabelDatabase, name)
	default:
		return b.stub(ontology.LabelBucket, name)
	}
}

// ── value helpers (Custodian dicts are heterogeneous) ───────────────

func str(v any) string {
	s, _ := v.(string)
	return s
}

func name(r map[string]any, fallback string) string {
	for _, raw := range slice(r["Tags"]) {
		t, _ := raw.(map[string]any)
		if strings.EqualFold(str(t["Key"]), "Name") {
			if v := str(t["Value"]); v != "" {
				return v
			}
		}
	}
	return fallback
}

// instanceProfile accepts either a string role name or {"Arn": ".../role"}.
func instanceProfile(r map[string]any) string {
	switch p := r["IamInstanceProfile"].(type) {
	case string:
		return p
	case map[string]any:
		arn := str(p["Arn"])
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			return arn[i+1:]
		}
		return arn
	}
	return ""
}

func slice(v any) []any {
	s, _ := v.([]any)
	return s
}

func boolish(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
