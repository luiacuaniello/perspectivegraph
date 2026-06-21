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
// Every field read here exists in real AWS/Custodian exports: EC2
// InstanceId/PublicIpAddress/IamInstanceProfile/Tags, ALB
// LoadBalancerName/Scheme/Tags, IAM RoleName/AttachedManagedPolicies, S3
// Name/Tags/Acl grants, RDS DBInstanceIdentifier/PubliclyAccessible/TagList.
//
// Two relationships AWS does not state directly are inferred and documented:
//
//   - LB --ROUTES_TO--> EC2 when both carry the same `app` tag (flat exports
//     do not include target-group membership);
//   - admin role --HAS_PERMISSION--> crown-jewel data stores in the same
//     export (AdministratorAccess grants everything in the account).
//
// Crown-jewel classification is data-driven via resource tags — see
// ingestion.CrownJewelFromTags.
package custodian

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
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

	g := &builder{nodes: map[string]ontology.Node{}, appOf: map[string]string{}}
	for _, pol := range b.Policies {
		for _, res := range pol.Resources {
			switch strings.ToLower(pol.Resource) {
			case "aws.ec2", "ec2", "vm":
				g.ec2(res)
			case "aws.iam-role", "iam-role", "iam":
				g.iamRole(res)
			case "aws.s3", "s3", "bucket":
				g.bucket(res)
			case "aws.rds", "rds", "database":
				g.database(res)
			case "aws.elb", "aws.elbv2", "elb", "loadbalancer":
				g.loadBalancer(res)
			}
		}
	}
	g.inferEdges()

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
	appOf map[string]string // node id -> `app` tag, for LB→EC2 inference
	lbs   []string          // load-balancer node ids
	vms   []string          // EC2 node ids
	admin []string          // admin-role node ids
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

// inferEdges adds the relationships flat exports don't state directly.
func (b *builder) inferEdges() {
	// LB routes to every EC2 sharing its `app` tag.
	for _, lb := range b.lbs {
		app := b.appOf[lb]
		if app == "" {
			continue
		}
		for _, vm := range b.vms {
			if strings.EqualFold(b.appOf[vm], app) {
				b.edge(ontology.EdgeRoutesTo, lb, vm, 0.9)
			}
		}
	}
	// AdministratorAccess reaches everything: connect admin roles to every
	// crown-jewel data store observed in the same export.
	for _, role := range b.admin {
		for id, n := range b.nodes {
			if (n.Label == ontology.LabelBucket || n.Label == ontology.LabelDatabase) &&
				n.Bool(ontology.PropCrownJewel) {
				b.edge(ontology.EdgeHasPermission, role, id, 0.7)
			}
		}
	}
}

func (b *builder) ec2(r map[string]any) {
	id := str(r["InstanceId"])
	if id == "" {
		return
	}
	tg := tags(r)
	nodeID := ontology.NewID(ontology.LabelVirtualMachine, id)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if ip := str(r["PublicIpAddress"]); ip != "" {
		props[ontology.PropInternetExposed] = true
		props["public_ip"] = ip
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
		b.appOf[nodeID] = app
	}
	if ingestion.CrownJewelFromTags(tg) {
		props[ontology.PropCrownJewel] = true
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelVirtualMachine, Name: nameFrom(tg, id), Properties: props})
	b.vms = append(b.vms, nodeID)

	if role := instanceProfile(r); role != "" {
		roleID := b.stub(ontology.LabelIAMRole, role)
		b.edge(ontology.EdgeAssumes, nodeID, roleID, 0.8)
	}
}

func (b *builder) iamRole(r map[string]any) {
	roleName := str(r["RoleName"])
	if roleName == "" {
		return
	}
	nodeID := ontology.NewID(ontology.LabelIAMRole, roleName)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if hasAdminPolicy(r) {
		// An admin role is itself a crown jewel: owning it is owning the account.
		props[ontology.PropCrownJewel] = true
		props["admin"] = true
		b.admin = append(b.admin, nodeID)
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelIAMRole, Name: roleName, Properties: props})
}

func (b *builder) bucket(r map[string]any) {
	name := str(r["Name"])
	if name == "" {
		return
	}
	tg := tags(r)
	props := map[string]any{}
	if publicACL(r) {
		props[ontology.PropInternetExposed] = true
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
	}
	if ingestion.CrownJewelFromTags(tg) {
		props[ontology.PropCrownJewel] = true
	}
	b.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelBucket, name), Label: ontology.LabelBucket, Name: name, Properties: props})
}

func (b *builder) database(r map[string]any) {
	id := first(str(r["DBInstanceIdentifier"]), str(r["Name"]))
	if id == "" {
		return
	}
	tg := tags(r)
	props := map[string]any{}
	if boolish(r["PubliclyAccessible"]) { // real RDS field
		props[ontology.PropInternetExposed] = true
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
	}
	if ingestion.CrownJewelFromTags(tg) {
		props[ontology.PropCrownJewel] = true
	}
	b.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelDatabase, id), Label: ontology.LabelDatabase, Name: id, Properties: props})
}

func (b *builder) loadBalancer(r map[string]any) {
	name := first(str(r["LoadBalancerName"]), str(r["Name"]))
	if name == "" {
		return
	}
	tg := tags(r)
	nodeID := ontology.NewID(ontology.LabelLoadBalancer, name)
	props := map[string]any{}
	if strings.EqualFold(str(r["Scheme"]), "internet-facing") {
		props[ontology.PropInternetExposed] = true
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
		b.appOf[nodeID] = app
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelLoadBalancer, Name: name, Properties: props})
	b.lbs = append(b.lbs, nodeID)
}

// ── value helpers (Custodian dicts are heterogeneous) ───────────────

func str(v any) string {
	s, _ := v.(string)
	return s
}

// tags flattens AWS tag lists ({"Key","Value"} under "Tags" or RDS "TagList")
// into a lowercase-keyed map.
func tags(r map[string]any) map[string]string {
	out := map[string]string{}
	for _, field := range []string{"Tags", "TagList"} {
		for _, raw := range slice(r[field]) {
			t, _ := raw.(map[string]any)
			if k := str(t["Key"]); k != "" {
				out[strings.ToLower(k)] = str(t["Value"])
			}
		}
	}
	return out
}

func nameFrom(tags map[string]string, fallback string) string {
	if v := tags["name"]; v != "" {
		return v
	}
	return fallback
}

// hasAdminPolicy reports whether the role has the AdministratorAccess managed
// policy attached (real field: AttachedManagedPolicies[].PolicyName/PolicyArn,
// present when the export enriches roles with their policies).
func hasAdminPolicy(r map[string]any) bool {
	for _, raw := range slice(r["AttachedManagedPolicies"]) {
		p, _ := raw.(map[string]any)
		if strings.EqualFold(str(p["PolicyName"]), "AdministratorAccess") ||
			strings.HasSuffix(str(p["PolicyArn"]), "policy/AdministratorAccess") {
			return true
		}
	}
	return false
}

// publicACL reports whether the bucket ACL grants to AllUsers (the classic
// public-bucket signal: Acl.Grants[].Grantee.URI ends in /AllUsers).
func publicACL(r map[string]any) bool {
	acl, _ := r["Acl"].(map[string]any)
	for _, raw := range slice(acl["Grants"]) {
		g, _ := raw.(map[string]any)
		grantee, _ := g["Grantee"].(map[string]any)
		if strings.HasSuffix(str(grantee["URI"]), "/AllUsers") {
			return true
		}
	}
	return false
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
