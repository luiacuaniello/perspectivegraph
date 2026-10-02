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
// Crown-jewel classification is data-driven via resource tags - see
// ingestion.CrownJewelFromTags.
//
// Identities are keyed the way the other AWS sources key them, so the same role or
// instance is one node whichever source reported it. A role is keyed on its ARN, as the
// iam, cloudnet and SSO collectors do: keyed on its name, it never met the role those
// sources describe, and it merged with any Kubernetes ClusterRole of the same name - an
// AWS role called "admin" and the ClusterRole "admin" every cluster ships became one node,
// and a namespace admin appeared to reach the account's S3 data. An instance is scoped to
// the bundle's account_id, as cloudnet scopes it.
//
// An instance's role comes from its instance profile, and EC2 reports only the profile.
// The profile's role is read from aws.iam-profile resources (or an InstanceProfileList on
// a role) when the export has them. Without them the role is guessed to share the
// profile's name - true of a profile the console creates, often false of one Terraform or
// CloudFormation creates - and that join is marked as inferred, at half the confidence.
// It used to be taken as fact, with the profile's name read as the role's: an instance
// whose profile was named differently reached a role nobody had defined, and no route.
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
	// Region is the Region the bundle was exported from, when it is one Region's
	// export. A resource's own ARN takes precedence.
	Region   string `json:"region"`
	Policies []struct {
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

	g := &builder{nodes: map[string]ontology.Node{}, appOf: map[string]string{}, regionOf: map[string]string{},
		account: b.AccountID, region: b.Region, profileRole: map[string]string{}}
	for _, pol := range b.Policies {
		for _, res := range pol.Resources {
			switch strings.ToLower(pol.Resource) {
			case "aws.ec2", "ec2", "vm":
				g.ec2(res)
			case "aws.iam-role", "iam-role", "iam":
				g.iamRole(res)
			case "aws.iam-profile", "iam-profile", "instance-profile":
				g.iamProfile(res)
			case "aws.s3", "s3", "bucket":
				g.bucket(res)
			case "aws.rds", "rds", "database":
				g.database(res)
			case "aws.elb", "aws.elbv2", "elb", "loadbalancer":
				g.loadBalancer(res)
			}
		}
	}
	g.linkInstanceRoles() // after every policy: the profiles may come after the instances
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
	// regionOf is the Region of a load balancer or instance when the export says it:
	// a load balancer only routes to instances in its own Region.
	regionOf map[string]string
	lbs      []string // load-balancer node ids
	vms      []string // EC2 node ids
	admin    []string // admin-role node ids

	account     string            // the bundle's account_id, "" when it has none
	region      string            // the bundle's region, "" when it has none
	profileRole map[string]string // instance-profile ARN (and name) -> role ARN
	pending     []instanceLink    // instances whose role is resolved once every policy is read
}

// instanceLink is an instance and the instance profile it runs with, waiting for the
// profile's role to be known.
type instanceLink struct {
	vm, profileARN, profileName string
	// httpTokens is the instance's IMDS setting, which decides how cheaply a foothold
	// on it becomes the role's credentials.
	httpTokens string
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
			if strings.EqualFold(b.appOf[vm], app) && sameRegion(b.regionOf[lb], b.regionOf[vm]) {
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
	nodeID := ontology.ScopedID(ontology.LabelVirtualMachine, b.account, id)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if b.account != "" {
		props[ontology.PropAccount] = b.account
	}
	if ip := str(r["PublicIpAddress"]); ip != "" {
		props[ontology.PropInternetExposed] = true
		props["public_ip"] = ip
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
		b.appOf[nodeID] = app
	}
	ingestion.MarkCrownJewelFromTags(props, tg)
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelVirtualMachine, Name: nameFrom(tg, id), Properties: props})
	b.vms = append(b.vms, nodeID)
	placement, _ := r["Placement"].(map[string]any)
	if region := first(ingestion.RegionFromZone(str(placement["AvailabilityZone"])), b.region); region != "" {
		b.regionOf[nodeID] = region
	}

	if arn, name := instanceProfile(r); name != "" {
		tokens, _ := r["MetadataOptions"].(map[string]any)
		b.pending = append(b.pending, instanceLink{vm: nodeID, profileARN: arn, profileName: name,
			httpTokens: str(tokens["HttpTokens"])})
	}
}

// profileNameConfidence is how far the name convention is trusted when the export says
// nothing about a profile's role: as likely as not, since the console keeps the names
// equal and infrastructure-as-code often does not.
const profileNameConfidence = 0.5

// linkInstanceRoles joins each instance to the role its profile carries: the role the
// export names when it has the profile, otherwise the role that shares the profile's name,
// marked as an inferred join at half the probability. The probability is the one the
// network source gives the same step, from the same IMDS setting.
func (b *builder) linkInstanceRoles() {
	for _, l := range b.pending {
		p := ingestion.IMDSAssumeProb(l.httpTokens)
		if arn := first(b.profileRole[l.profileARN], b.profileRole[l.profileName]); arn != "" {
			b.edge(ontology.EdgeAssumes, l.vm, b.roleNode(arn, ""), p)
			continue
		}
		account := first(ingestion.AccountFromARN(l.profileARN), b.account)
		roleID := b.roleNode(roleARN(account, l.profileName), l.profileName)
		b.edges = append(b.edges, ontology.Edge{
			Type: ontology.EdgeAssumes, From: l.vm, To: roleID,
			ExploitProbability: p * profileNameConfidence,
			Properties: map[string]any{
				ontology.PropResolutionMethod:     "instance-profile-name",
				ontology.PropResolutionConfidence: profileNameConfidence,
			},
		})
	}
}

// roleNode returns the id of the role with this ARN, adding a node for it when the export
// did not list the role itself.
func (b *builder) roleNode(arn, name string) string {
	id := ontology.NewID(ontology.LabelIAMRole, arn)
	if _, ok := b.nodes[id]; !ok {
		if name == "" {
			name = arn[strings.LastIndex(arn, "/")+1:]
		}
		props := map[string]any{}
		if acct := ingestion.AccountFromARN(arn); acct != "" {
			props[ontology.PropAccount] = acct
		}
		b.nodes[id] = ontology.Node{ID: id, Label: ontology.LabelIAMRole, Name: name, Properties: props}
	}
	return id
}

// roleARN is the ARN of a role with no path, the one AWS gives a role created without one.
// It stands in for a role the export names but gives no Arn for.
func roleARN(account, name string) string {
	return "arn:aws:iam::" + account + ":role/" + name
}

func (b *builder) iamRole(r map[string]any) {
	roleName := str(r["RoleName"])
	if roleName == "" {
		return
	}
	arn := str(r["Arn"])
	if arn == "" {
		arn = roleARN(b.account, roleName)
	}
	nodeID := ontology.NewID(ontology.LabelIAMRole, arn)
	props := map[string]any{ontology.PropARN: str(r["Arn"])}
	if acct := first(ingestion.AccountFromARN(arn), b.account); acct != "" {
		props[ontology.PropAccount] = acct
	}
	// GetAccountAuthorizationDetails lists a role's instance profiles; take them when a
	// role arrives in that shape.
	for _, ip := range slice(r["InstanceProfileList"]) {
		if m, ok := ip.(map[string]any); ok {
			b.mapProfile(str(m["Arn"]), str(m["InstanceProfileName"]), arn)
		}
	}
	if hasAdminPolicy(r) {
		// An admin role is itself a crown jewel: owning it is owning the account.
		props[ontology.PropCrownJewel] = true
		props["admin"] = true
		b.admin = append(b.admin, nodeID)
	}
	b.upsert(ontology.Node{ID: nodeID, Label: ontology.LabelIAMRole, Name: roleName, Properties: props})
}

// iamProfile reads an instance profile (Custodian's aws.iam-profile: ListInstanceProfiles)
// and the role it carries - at most one, by AWS's own rule.
func (b *builder) iamProfile(r map[string]any) {
	for _, ro := range slice(r["Roles"]) {
		m, ok := ro.(map[string]any)
		if !ok {
			continue
		}
		arn := str(m["Arn"])
		if arn == "" && str(m["RoleName"]) != "" {
			arn = roleARN(first(ingestion.AccountFromARN(str(r["Arn"])), b.account), str(m["RoleName"]))
		}
		if arn != "" {
			b.mapProfile(str(r["Arn"]), str(r["InstanceProfileName"]), arn)
			return
		}
	}
}

func (b *builder) mapProfile(profileARN, profileName, roleARN string) {
	if profileARN != "" {
		b.profileRole[profileARN] = roleARN
	}
	if profileName != "" {
		b.profileRole[profileName] = roleARN
	}
}

func (b *builder) bucket(r map[string]any) {
	name := str(r["Name"])
	if name == "" {
		return
	}
	tg := tags(r)
	props := map[string]any{}
	if granted, readable := publicGrant(r); granted {
		props[ontology.PropInternetExposed] = true
		// A public READ grant hands the data to anyone: the bucket is not a door into the
		// estate but already open, and a crown jewel that is open is compromised as it
		// stands. A write-only grant is exposure, not disclosure.
		if readable {
			props[ontology.PropPublicAccess] = true
		}
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
	}
	ingestion.MarkCrownJewelFromTags(props, tg)
	b.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelBucket, name), Label: ontology.LabelBucket, Name: name, Properties: props})
}

func (b *builder) database(r map[string]any) {
	id := first(str(r["DBInstanceIdentifier"]), str(r["Name"]))
	if id == "" {
		return
	}
	tg := tags(r)
	props := map[string]any{}
	if b.account != "" {
		props[ontology.PropAccount] = b.account
	}
	region := first(ingestion.RegionFromARN(str(r["DBInstanceArn"])), b.region)
	if region != "" {
		props["region"] = region
	}
	if boolish(r["PubliclyAccessible"]) { // real RDS field
		props[ontology.PropInternetExposed] = true
	}
	if app := tg["app"]; app != "" {
		props["app"] = app
	}
	ingestion.MarkCrownJewelFromTags(props, tg)
	// An RDS identifier, like a load balancer's name, is unique only within one account
	// and Region: prod-db in two accounts, or in two Regions of one account, is two
	// databases, and keyed by name they were one, with each other's exposure,
	// classification and routes. The Region comes from the resource's ARN, else from
	// the bundle; buckets stay unscoped, since their names are unique across AWS.
	b.upsert(ontology.Node{ID: ingestion.RegionalID(ontology.LabelDatabase, b.account, region, id), Label: ontology.LabelDatabase, Name: id, Properties: props})
}

func (b *builder) loadBalancer(r map[string]any) {
	name := first(str(r["LoadBalancerName"]), str(r["Name"]))
	if name == "" {
		return
	}
	tg := tags(r)
	region := first(ingestion.RegionFromARN(str(r["LoadBalancerArn"])), b.region)
	nodeID := ingestion.RegionalID(ontology.LabelLoadBalancer, b.account, region, name) // unique per account and Region, see database
	props := map[string]any{}
	if b.account != "" {
		props[ontology.PropAccount] = b.account
	}
	if region != "" {
		props["region"] = region
		b.regionOf[nodeID] = region
	}
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

// publicGrant reports whether the bucket ACL grants anything to everyone - the classic
// public-bucket signal, Acl.Grants[].Grantee.URI ending in /AllUsers, or in
// /AuthenticatedUsers, which is any AWS account in the world rather than the owner's -
// and whether one of those grants lets them read the objects (READ or FULL_CONTROL).
func publicGrant(r map[string]any) (granted, readable bool) {
	acl, _ := r["Acl"].(map[string]any)
	for _, raw := range slice(acl["Grants"]) {
		g, _ := raw.(map[string]any)
		grantee, _ := g["Grantee"].(map[string]any)
		uri := str(grantee["URI"])
		if !strings.HasSuffix(uri, "/AllUsers") && !strings.HasSuffix(uri, "/AuthenticatedUsers") {
			continue
		}
		granted = true
		switch strings.ToUpper(str(g["Permission"])) {
		case "READ", "FULL_CONTROL":
			readable = true
		}
	}
	return granted, readable
}

// instanceProfile returns the ARN and the name of an instance's profile. EC2 reports it as
// {"Arn": ".../instance-profile/NAME", "Id": ...}; a flattened export may give the name
// alone. It is the PROFILE's name: the role inside it can be named anything.
func instanceProfile(r map[string]any) (arn, name string) {
	switch p := r["IamInstanceProfile"].(type) {
	case string:
		if strings.HasPrefix(p, "arn:") {
			return p, p[strings.LastIndex(p, "/")+1:]
		}
		return "", p
	case map[string]any:
		arn := str(p["Arn"])
		return arn, arn[strings.LastIndex(arn, "/")+1:]
	}
	return "", ""
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

// sameRegion reports whether a load balancer and an instance can be in one Region. An
// unknown Region matches anything, as before Regions were read; a Local Zone or
// Wavelength zone (us-west-2-lax-1) belongs to its parent Region.
func sameRegion(a, b string) bool {
	return a == "" || b == "" || a == b || strings.HasPrefix(a, b+"-") || strings.HasPrefix(b, a+"-")
}
