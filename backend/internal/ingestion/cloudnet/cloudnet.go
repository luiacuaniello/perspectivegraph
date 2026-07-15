// Package cloudnet discovers cloud network reachability - who can reach whom -
// from security groups, instances and VPC peerings, and emits it as ontology
// relationships. It answers the lateral-movement question scanners can't:
//
//	0.0.0.0/0 ingress     → the instance is internet_exposed (a path seed)
//	SG-to-SG ingress rule → instances in the source SG ──CONNECTS_TO──▶ instances in the target SG
//	VPC peering           → VPC ──CONNECTS_TO──▶ VPC
//	IAM instance profile  → instance ──ASSUMES──▶ IAM_Role
//
// That last edge is the IMDS hop, and it is what joins the network half of the graph to
// the identity half: without it "the internet reaches this box" and "this role owns the
// account" stay in disconnected components, and the canonical AWS path (internet →
// instance → IMDS → role → privilege escalation) cannot form. EC2 reports only the
// *profile* ARN, so the bundle's optional `instance_profiles` (iam list-instance-profiles
// shape) resolves it to the role, keyed by ARN to match the iam collector. The hop's
// probability follows the instance's real IMDS posture: IMDSv2 required makes a blind SSRF
// insufficient, IMDSv1 hands the credentials to a single GET.
//
// Reachability precision (opt-in, when the input carries it): a security group
// open to 0.0.0.0/0 is *not* enough to reach an instance - the traffic also needs a
// route to an internet gateway and a permitting network ACL. When the bundle
// supplies subnets + route_tables + network_acls (real describe-subnets /
// describe-route-tables / describe-network-acls shapes), an SG-open instance is
// flagged internet_exposed ONLY if its subnet has a 0.0.0.0/0 → igw route AND its
// NACL admits inbound from the internet. This removes the classic false positive:
// an open SG on an instance in a *private* subnet. When that data is absent the
// SG-only heuristic still applies, so existing feeds degrade gracefully.
//
// Input is a bundle of real AWS shapes (describe-security-groups /
// describe-instances / describe-vpc-peering-connections, plus the optional
// route/NACL shapes). Sensitive-asset classification is tag-driven
// (ingestion.CrownJewelFromTags).
package cloudnet

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type bundle struct {
	Provider       string `json:"provider"`
	SecurityGroups []struct {
		GroupID       string `json:"GroupId"`
		GroupName     string `json:"GroupName"`
		IpPermissions []struct {
			IpRanges []struct {
				CidrIp string `json:"CidrIp"`
			} `json:"IpRanges"`
			UserIdGroupPairs []struct {
				GroupID string `json:"GroupId"`
			} `json:"UserIdGroupPairs"`
		} `json:"IpPermissions"`
	} `json:"security_groups"`
	Instances []struct {
		InstanceID     string `json:"InstanceId"`
		SubnetID       string `json:"SubnetId"` // optional: enables route/NACL-aware exposure
		SecurityGroups []struct {
			GroupID string `json:"GroupId"`
		} `json:"SecurityGroups"`
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
		// The *profile* ARN ec2 reports (the role behind it lives in IAM), and the IMDS
		// posture that decides how cheaply a foothold becomes that role's credentials.
		IamInstanceProfile *struct {
			Arn string `json:"Arn"`
		} `json:"IamInstanceProfile"`
		MetadataOptions *struct {
			HTTPTokens string `json:"HttpTokens"`
		} `json:"MetadataOptions"`
	} `json:"instances"`
	VPCPeerings []struct {
		RequesterVpcInfo struct {
			VpcID string `json:"VpcId"`
		} `json:"RequesterVpcInfo"`
		AccepterVpcInfo struct {
			VpcID string `json:"VpcId"`
		} `json:"AccepterVpcInfo"`
	} `json:"vpc_peerings"`
	// Optional network-layer detail: when present, an SG-open instance is only
	// internet_exposed if its subnet actually routes to an IGW and its NACL admits
	// the internet. Absent → the SG-only heuristic stands (backward-compatible).
	Subnets []struct {
		SubnetID     string `json:"SubnetId"`
		RouteTableID string `json:"RouteTableId"`
		NetworkACLID string `json:"NetworkAclId"`
	} `json:"subnets"`
	RouteTables []struct {
		RouteTableID string `json:"RouteTableId"`
		Routes       []struct {
			DestinationCidrBlock string `json:"DestinationCidrBlock"`
			GatewayID            string `json:"GatewayId"`
			// Non-internet-gateway default-route targets (all mean "private egress"):
			NatGatewayID     string `json:"NatGatewayId"`
			TransitGatewayID string `json:"TransitGatewayId"`
			VpcPeeringConnID string `json:"VpcPeeringConnectionId"`
			EgressOnlyIGWID  string `json:"EgressOnlyInternetGatewayId"`
		} `json:"Routes"`
	} `json:"route_tables"`
	NetworkACLs []struct {
		NetworkACLID string `json:"NetworkAclId"`
		Entries      []struct {
			RuleNumber int    `json:"RuleNumber"`
			Egress     bool   `json:"Egress"`
			CidrBlock  string `json:"CidrBlock"`
			RuleAction string `json:"RuleAction"` // "allow" | "deny"
		} `json:"Entries"`
	} `json:"network_acls"`
	// Optional (iam list-instance-profiles shape): resolves an instance's profile ARN to
	// the role it carries. Absent → no instance --ASSUMES--> role edges.
	InstanceProfiles []struct {
		Arn   string `json:"Arn"`
		Roles []struct {
			Arn      string `json:"Arn"`
			RoleName string `json:"RoleName"`
		} `json:"Roles"`
	} `json:"instance_profiles"`
}

// roleRef is the role an instance profile carries: the ARN keys the node (matching the
// iam collector, which ids roles by ARN) and the name labels it.
type roleRef struct{ arn, name string }

// imdsAssumeProb is how likely a foothold on an instance becomes credentials for its
// role. With IMDSv2 enforced (HttpTokens=required) a blind SSRF cannot mint the token, so
// the attacker needs code execution first; with IMDSv1 still answering, one GET is enough.
// Driven by the instance's real metadata configuration rather than a guessed constant.
func imdsAssumeProb(httpTokens string) float64 {
	if strings.EqualFold(httpTokens, "required") {
		return 0.6
	}
	return 0.9
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "cloudnet" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode cloudnet bundle: %w", err)
	}

	// Which SGs open to the internet, and which SGs a given SG admits ingress from.
	sgInternet := map[string]bool{}
	sgFromSG := map[string][]string{} // targetSG -> [sourceSG…]
	for _, sg := range b.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, rng := range perm.IpRanges {
				if rng.CidrIp == "0.0.0.0/0" || rng.CidrIp == "::/0" {
					sgInternet[sg.GroupID] = true
				}
			}
			for _, pair := range perm.UserIdGroupPairs {
				if pair.GroupID != "" {
					sgFromSG[sg.GroupID] = append(sgFromSG[sg.GroupID], pair.GroupID)
				}
			}
		}
	}

	// Optional network-layer maps: subnet → route table / NACL, whether a route table
	// reaches an internet gateway, and whether a NACL admits internet ingress. Empty
	// when the bundle carries no subnet/route/NACL data (the SG-only path).
	subnetRT, subnetNacl := map[string]string{}, map[string]string{}
	for _, s := range b.Subnets {
		if s.RouteTableID != "" {
			subnetRT[s.SubnetID] = s.RouteTableID
		}
		if s.NetworkACLID != "" {
			subnetNacl[s.SubnetID] = s.NetworkACLID
		}
	}
	// Classify each route table's default (0.0.0.0/0 or ::/0) route by target. ONLY an
	// internet-gateway target makes a subnet inbound-reachable; a NAT/transit-gateway/
	// peering/egress-only-IGW target is private egress - recorded so the audit note can
	// say *why* an SG-open instance is not actually exposed.
	rtHasIgw := map[string]bool{}
	rtEgressVia := map[string]string{}
	for _, rt := range b.RouteTables {
		for _, r := range rt.Routes {
			if r.DestinationCidrBlock != "0.0.0.0/0" && r.DestinationCidrBlock != "::/0" {
				continue
			}
			switch {
			case strings.HasPrefix(r.GatewayID, "igw-"):
				rtHasIgw[rt.RouteTableID] = true
			case r.NatGatewayID != "":
				rtEgressVia[rt.RouteTableID] = "a NAT gateway"
			case r.TransitGatewayID != "":
				rtEgressVia[rt.RouteTableID] = "a transit gateway"
			case r.VpcPeeringConnID != "":
				rtEgressVia[rt.RouteTableID] = "a VPC peering connection"
			case r.EgressOnlyIGWID != "" || strings.HasPrefix(r.GatewayID, "eigw-"):
				rtEgressVia[rt.RouteTableID] = "an egress-only internet gateway"
			}
		}
	}
	// A NACL is stateless and evaluated in ascending rule order, first match wins. For
	// "does it admit the internet", the first ingress entry on 0.0.0.0/0 decides; no
	// such entry means the implicit deny applies.
	naclNetAllow := map[string]bool{}
	for _, n := range b.NetworkACLs {
		es := n.Entries
		sort.Slice(es, func(i, j int) bool { return es[i].RuleNumber < es[j].RuleNumber })
		for _, e := range es {
			if e.Egress {
				continue
			}
			if e.CidrBlock == "0.0.0.0/0" || e.CidrBlock == "::/0" {
				naclNetAllow[n.NetworkACLID] = strings.EqualFold(e.RuleAction, "allow")
				break
			}
		}
		if _, seen := naclNetAllow[n.NetworkACLID]; !seen {
			naclNetAllow[n.NetworkACLID] = false // no internet ingress rule → implicit deny
		}
	}

	// Instance profile ARN → the role it carries. EC2 reports only the profile; this is
	// the join that turns "a box reachable on the network" into "an identity an attacker
	// inherits" - the hop that connects the network half of the graph to the identity half.
	// A profile carries at most one role in practice.
	profileRoles := map[string]roleRef{}
	for _, p := range b.InstanceProfiles {
		if p.Arn == "" || len(p.Roles) == 0 || p.Roles[0].Arn == "" {
			continue
		}
		profileRoles[p.Arn] = roleRef{arn: p.Roles[0].Arn, name: p.Roles[0].RoleName}
	}

	g := &builder{nodes: map[string]ontology.Node{}}
	instancesBySG := map[string][]string{} // sg -> [instance node id…]

	for _, inst := range b.Instances {
		if inst.InstanceID == "" {
			continue
		}
		id := ontology.NewID(ontology.LabelVirtualMachine, inst.InstanceID)
		props := map[string]any{}
		tags := map[string]string{}
		for _, t := range inst.Tags {
			tags[t.Key] = t.Value
		}
		sgOpen := false
		for _, sg := range inst.SecurityGroups {
			instancesBySG[sg.GroupID] = append(instancesBySG[sg.GroupID], id)
			if sgInternet[sg.GroupID] {
				sgOpen = true
			}
		}
		if sgOpen {
			// An open SG is necessary but not sufficient: the traffic also needs a route
			// to the internet and a permitting NACL. With that data, a private-subnet
			// instance is correctly NOT exposed; without it, the SG alone stands.
			if reachable, note := internetReachable(inst.SubnetID, subnetRT, subnetNacl, rtHasIgw, rtEgressVia, naclNetAllow); reachable {
				props[ontology.PropInternetExposed] = true
			} else if note != "" {
				props["net_reachability"] = note
			}
		}
		if ingestion.CrownJewelFromTags(tags) {
			props[ontology.PropCrownJewel] = true
		}
		name := tags["Name"]
		if name == "" {
			name = inst.InstanceID
		}
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelVirtualMachine, Name: name, Properties: props})

		// instance --ASSUMES--> its instance-profile role. Without this the network and
		// identity halves never touch, and the canonical AWS path (internet → instance →
		// IMDS → role → privilege escalation) cannot form at all. The role node is keyed by
		// ARN to match the iam collector, so the two feeds converge on one node.
		if ip := inst.IamInstanceProfile; ip != nil {
			if r, ok := profileRoles[ip.Arn]; ok {
				roleID := ontology.NewID(ontology.LabelIAMRole, r.arn)
				g.upsert(ontology.Node{ID: roleID, Label: ontology.LabelIAMRole, Name: r.name})
				tokens := ""
				if inst.MetadataOptions != nil {
					tokens = inst.MetadataOptions.HTTPTokens
				}
				g.edge(ontology.EdgeAssumes, id, roleID, imdsAssumeProb(tokens))
			}
		}
	}

	// SG-to-SG ingress → instances in the source SG can reach instances in the
	// target SG. This is the discovered lateral-reachability edge.
	for targetSG, sources := range sgFromSG {
		for _, srcSG := range sources {
			for _, from := range instancesBySG[srcSG] {
				for _, to := range instancesBySG[targetSG] {
					if from != to {
						g.edge(ontology.EdgeConnectsTo, from, to, 0.8)
					}
				}
			}
		}
	}

	// VPC peering → reachability between VPCs.
	for _, peer := range b.VPCPeerings {
		a, z := peer.RequesterVpcInfo.VpcID, peer.AccepterVpcInfo.VpcID
		if a == "" || z == "" {
			continue
		}
		aID := g.stub(ontology.LabelVPC, a)
		zID := g.stub(ontology.LabelVPC, z)
		g.edge(ontology.EdgeConnectsTo, aID, zID, 0.7)
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      g.nodeSlice(),
		Edges:      g.edges,
	}}, nil
}

// internetReachable decides whether an already-SG-open instance is *actually*
// reachable from the internet, using the optional route/NACL maps. It returns a
// short note when the instance is SG-open but blocked (for the UI / audit). With no
// subnet/route data it defaults to reachable - the SG-only heuristic, so feeds that
// don't carry the network layer degrade gracefully instead of losing every seed.
func internetReachable(subnetID string, subnetRT, subnetNacl map[string]string, rtHasIgw map[string]bool, rtEgressVia map[string]string, naclNetAllow map[string]bool) (bool, string) {
	if subnetID == "" {
		return true, "" // no subnet info on the instance → SG-only
	}
	rt, known := subnetRT[subnetID]
	if !known {
		return true, "" // subnet not described → SG-only
	}
	if !rtHasIgw[rt] {
		if via := rtEgressVia[rt]; via != "" {
			return false, "SG-open but in a private subnet (egress via " + via + ", not an internet gateway)"
		}
		return false, "SG-open but in a private subnet (no internet-gateway route)"
	}
	if nacl := subnetNacl[subnetID]; nacl != "" {
		if allow, seen := naclNetAllow[nacl]; seen && !allow {
			return false, "SG-open and routed, but the network ACL denies internet ingress"
		}
	}
	return true, ""
}

type builder struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
}

func (b *builder) upsert(n ontology.Node) {
	if existing, ok := b.nodes[n.ID]; ok {
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
