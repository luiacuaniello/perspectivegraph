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
// Reachability precision (opt-in, when the input carries it), decided port by port and
// per address family: a security group open to 0.0.0.0/0 or ::/0 is *not* enough to
// reach an instance - the traffic also needs a public address on the instance, a route
// to an internet gateway for that family and a network ACL that lets the port through,
// first match by rule number. When the bundle supplies addresses, subnets, route_tables
// and network_acls (real describe-* shapes), an instance is internet_exposed only on the
// ports that pass all of them, recorded as exposed_ports (and exposed_management_ports,
// the shells, control planes and databases among them); ICMP alone is no way in. This
// removes the classic false positives - an open SG on an instance in a *private* subnet,
// or without a public address, or behind an ACL that allows only 443. When that data is
// absent the SG alone decides, so existing feeds degrade gracefully. The verdict is
// written true or false every time (network_exposed), so closing a group retracts it.
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
			// IpProtocol is "tcp", "udp", "icmp", "-1" (all) or a number; absent means all,
			// which is what a bundle that predates ports meant.
			IpProtocol string `json:"IpProtocol"`
			FromPort   *int   `json:"FromPort"`
			ToPort     *int   `json:"ToPort"`
			IpRanges   []struct {
				CidrIp string `json:"CidrIp"`
			} `json:"IpRanges"`
			Ipv6Ranges []struct {
				CidrIpv6 string `json:"CidrIpv6"`
			} `json:"Ipv6Ranges"`
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
		// The addresses the internet can reach it on. describe-instances always carries
		// PrivateIpAddress, so its presence says the rest would be there if it existed.
		PrivateIPAddress  string `json:"PrivateIpAddress"`
		PublicIPAddress   string `json:"PublicIpAddress"`
		IPv6Address       string `json:"Ipv6Address"`
		NetworkInterfaces []struct {
			Association *struct {
				PublicIP string `json:"PublicIp"`
			} `json:"Association"`
			IPv6Addresses []struct {
				IPv6Address string `json:"Ipv6Address"`
			} `json:"Ipv6Addresses"`
		} `json:"NetworkInterfaces"`
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
			DestinationCidrBlock     string `json:"DestinationCidrBlock"`
			DestinationIpv6CidrBlock string `json:"DestinationIpv6CidrBlock"`
			GatewayID                string `json:"GatewayId"`
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
			RuleNumber    int    `json:"RuleNumber"`
			Egress        bool   `json:"Egress"`
			CidrBlock     string `json:"CidrBlock"`
			Ipv6CidrBlock string `json:"Ipv6CidrBlock"`
			RuleAction    string `json:"RuleAction"` // "allow" | "deny"
			// Protocol is "-1" (all), "6" (tcp), "17" (udp)…; absent means all.
			Protocol  string `json:"Protocol"`
			PortRange *struct {
				From *int `json:"From"`
				To   *int `json:"To"`
			} `json:"PortRange"`
		} `json:"Entries"`
	} `json:"network_acls"`
	// Optional: ECS services running in awsvpc mode, flattened from describe-services and
	// describe-task-definition. A service is a workload with security groups, subnets and,
	// maybe, a public address - exposed the way an instance is - and a task role its
	// containers fetch from the task metadata endpoint.
	ECSServices []struct {
		ServiceArn     string   `json:"serviceArn"`
		ServiceName    string   `json:"serviceName"`
		ClusterArn     string   `json:"clusterArn"`
		TaskRoleArn    string   `json:"taskRoleArn"`
		AssignPublicIP string   `json:"assignPublicIp"` // ENABLED | DISABLED
		SecurityGroups []string `json:"securityGroups"`
		Subnets        []string `json:"subnets"`
	} `json:"ecs_services"`
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

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "cloudnet" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode cloudnet bundle: %w", err)
	}

	// The ports each SG opens to the internet, per address family, and the ports it
	// admits from each other SG. AWS lists IPv6 sources under Ipv6Ranges; reading ::/0
	// only out of IpRanges, as this did before, never saw an IPv6-open group.
	sgInternet := map[string]familyPorts{}
	sgFromSG := map[string]map[string]ingestion.PortSet{} // targetSG -> sourceSG -> ports
	for _, sg := range b.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			ports := ingestion.RulePorts(perm.IpProtocol, perm.FromPort, perm.ToPort)
			open := sgInternet[sg.GroupID]
			for _, rng := range perm.IpRanges {
				switch rng.CidrIp {
				case "0.0.0.0/0":
					open.v4 = open.v4.Union(ports)
				case "::/0": // tolerated: a hand-assembled bundle may put it here
					open.v6 = open.v6.Union(ports)
				}
			}
			for _, rng := range perm.Ipv6Ranges {
				if rng.CidrIpv6 == "::/0" {
					open.v6 = open.v6.Union(ports)
				}
			}
			sgInternet[sg.GroupID] = open
			for _, pair := range perm.UserIdGroupPairs {
				if pair.GroupID == "" {
					continue
				}
				if sgFromSG[sg.GroupID] == nil {
					sgFromSG[sg.GroupID] = map[string]ingestion.PortSet{}
				}
				sgFromSG[sg.GroupID][pair.GroupID] = sgFromSG[sg.GroupID][pair.GroupID].Union(ports)
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
	rtIgw := map[string]familyFlags{}
	rtEgressVia := map[string]string{}
	for _, rt := range b.RouteTables {
		for _, r := range rt.Routes {
			v4 := r.DestinationCidrBlock == "0.0.0.0/0"
			v6 := r.DestinationIpv6CidrBlock == "::/0" || r.DestinationCidrBlock == "::/0"
			if !v4 && !v6 {
				continue
			}
			switch {
			case strings.HasPrefix(r.GatewayID, "igw-"):
				f := rtIgw[rt.RouteTableID]
				f.v4, f.v6 = f.v4 || v4, f.v6 || v6
				rtIgw[rt.RouteTableID] = f
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
	// A NACL is stateless and evaluated in ascending rule order, first match wins, port
	// by port: "allow 443, then deny all" lets 443 through and nothing else. Only the
	// entries on the whole internet (0.0.0.0/0, ::/0) decide for traffic from it; what
	// none of them decides falls to the implicit deny. It used to be the first internet
	// entry alone, whatever its ports - so an allow on 443 opened every port.
	nacls := map[string]familyRules{}
	for _, n := range b.NetworkACLs {
		es := n.Entries
		sort.Slice(es, func(i, j int) bool { return es[i].RuleNumber < es[j].RuleNumber })
		var rules familyRules
		for _, e := range es {
			if e.Egress {
				continue
			}
			var from, to *int
			if e.PortRange != nil {
				from, to = e.PortRange.From, e.PortRange.To
			}
			rule := ingestion.FirewallRule{
				Ports: ingestion.RulePorts(e.Protocol, from, to),
				Allow: strings.EqualFold(e.RuleAction, "allow"),
			}
			if e.CidrBlock == "0.0.0.0/0" {
				rules.v4 = append(rules.v4, rule)
			}
			if e.Ipv6CidrBlock == "::/0" || e.CidrBlock == "::/0" {
				rules.v6 = append(rules.v6, rule)
			}
		}
		nacls[n.NetworkACLID] = rules
	}
	net := netLayer{subnetRT: subnetRT, subnetNacl: subnetNacl, rtIgw: rtIgw, rtEgressVia: rtEgressVia, nacls: nacls}

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

	g := &builder{nodes: map[string]ontology.Node{}, account: opts.Account}
	instancesBySG := map[string][]string{} // sg -> [instance node id…]

	for _, inst := range b.Instances {
		if inst.InstanceID == "" {
			continue
		}
		// Account-scoped: two accounts can hand out the same instance id, and merging
		// them would invent a machine that spans both - and the paths through it.
		id := ontology.ScopedID(ontology.LabelVirtualMachine, opts.Account, inst.InstanceID)
		props := map[string]any{}
		if opts.Account != "" {
			props[ontology.PropAccount] = opts.Account
		}
		tags := map[string]string{}
		for _, t := range inst.Tags {
			tags[t.Key] = t.Value
		}
		var open familyPorts
		for _, sg := range inst.SecurityGroups {
			instancesBySG[sg.GroupID] = append(instancesBySG[sg.GroupID], id)
			open.v4 = open.v4.Union(sgInternet[sg.GroupID].v4)
			open.v6 = open.v6.Union(sgInternet[sg.GroupID].v6)
		}
		// An open SG is necessary but not sufficient: the traffic also needs an address
		// the internet can reach, a route to an internet gateway and a NACL that lets the
		// port through. Without that data, the SG alone stands.
		addr := addresses{known: inst.PrivateIPAddress != "", v4: inst.PublicIPAddress != "", v6: inst.IPv6Address != ""}
		for _, ni := range inst.NetworkInterfaces {
			addr.v4 = addr.v4 || (ni.Association != nil && ni.Association.PublicIP != "")
			addr.v6 = addr.v6 || len(ni.IPv6Addresses) > 0
		}
		exposed, note := internetExposure(open, inst.SubnetID, addr, net)
		// The verdict is written either way, and so are the ports, empty when nothing is
		// reached: properties accumulate across ingests, and one written only when true is
		// never retracted - closing a security group used to leave the instance exposed.
		props[ontology.PropNetworkExposed] = exposed.Transport()
		props[propExposedPorts], props[propExposedManagement] = "", ""
		if exposed.Transport() {
			props[ontology.PropInternetExposed] = true
			props[propExposedPorts] = exposed.String()
			props[propExposedManagement] = exposed.Management().String()
		}
		if note != "" {
			props["net_reachability"] = note
		}
		ingestion.MarkCrownJewelFromTags(props, tags)
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
				g.edge(ontology.EdgeAssumes, id, roleID, ingestion.IMDSAssumeProb(tokens))
			}
		}
	}

	// ECS services: exposed by the same rules as an instance, in whichever of their subnets
	// a task lands, with a public address only when the service assigns one - and holding
	// the task role, which every container of the task can fetch.
	for _, svc := range b.ECSServices {
		if svc.ServiceArn == "" {
			continue
		}
		id := ontology.NewID(ontology.LabelContainer, svc.ServiceArn)
		props := map[string]any{ontology.PropARN: svc.ServiceArn, "ecs_cluster": svc.ClusterArn[strings.LastIndex(svc.ClusterArn, "/")+1:]}
		if acct := ingestion.AccountFromARN(svc.ServiceArn); acct != "" {
			props[ontology.PropAccount] = acct
		}
		var open familyPorts
		for _, sg := range svc.SecurityGroups {
			instancesBySG[sg] = append(instancesBySG[sg], id)
			open.v4 = open.v4.Union(sgInternet[sg].v4)
			open.v6 = open.v6.Union(sgInternet[sg].v6)
		}
		addr := addresses{known: true, v4: strings.EqualFold(svc.AssignPublicIP, "ENABLED")}
		subnets := svc.Subnets
		if len(subnets) == 0 {
			subnets = []string{""}
		}
		exposed, notes := ingestion.PortSet{}, map[string]bool{}
		for _, subnet := range subnets {
			e, note := internetExposure(open, subnet, addr, net)
			exposed = exposed.Union(e)
			if note != "" {
				notes[note] = true
			}
		}
		props[ontology.PropNetworkExposed] = exposed.Transport()
		props[propExposedPorts], props[propExposedManagement] = "", ""
		if exposed.Transport() {
			props[ontology.PropInternetExposed] = true
			props[propExposedPorts] = exposed.String()
			props[propExposedManagement] = exposed.Management().String()
		}
		if len(notes) > 0 {
			ns := make([]string, 0, len(notes))
			for n := range notes {
				ns = append(ns, n)
			}
			sort.Strings(ns)
			props["net_reachability"] = strings.Join(ns, "; ")
		}
		name := first(svc.ServiceName, svc.ServiceArn[strings.LastIndex(svc.ServiceArn, "/")+1:])
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelContainer, Name: name, Properties: props})
		if svc.TaskRoleArn != "" {
			roleID := ontology.NewID(ontology.LabelIAMRole, svc.TaskRoleArn)
			g.upsert(ontology.Node{ID: roleID, Label: ontology.LabelIAMRole, Name: svc.TaskRoleArn[strings.LastIndex(svc.TaskRoleArn, "/")+1:]})
			g.edge(ontology.EdgeAssumes, id, roleID, ecsTaskRoleProb)
		}
	}

	// SG-to-SG ingress → instances in the source SG can reach instances in the
	// target SG, on the ports the rules name. This is the discovered
	// lateral-reachability edge; one per pair of instances, however many groups admit it.
	type pair struct{ from, to string }
	lateral := map[pair]ingestion.PortSet{}
	for targetSG, sources := range sgFromSG {
		for srcSG, ports := range sources {
			for _, from := range instancesBySG[srcSG] {
				for _, to := range instancesBySG[targetSG] {
					if from != to {
						k := pair{from, to}
						lateral[k] = lateral[k].Union(ports)
					}
				}
			}
		}
	}
	pairs := make([]pair, 0, len(lateral))
	for k := range lateral {
		pairs = append(pairs, k)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].from+pairs[i].to < pairs[j].from+pairs[j].to
	})
	for _, k := range pairs {
		// ICMP alone between two groups is a ping, not a way in.
		if ports := lateral[k]; ports.Transport() {
			g.edges = append(g.edges, ontology.Edge{Type: ontology.EdgeConnectsTo, From: k.from, To: k.to,
				ExploitProbability: 0.8, Properties: map[string]any{propPorts: ports.String()}})
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

// ecsTaskRoleProb is code running in a task becoming its task role: the credentials are
// one request to the task metadata endpoint away, from any container in the task.
const ecsTaskRoleProb = 0.9

// first returns the first non-empty value.
func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Node and edge properties for the ports exposure is decided on.
const (
	propExposedPorts      = "exposed_ports"            // what the internet reaches, e.g. "tcp/22, tcp/443"
	propExposedManagement = "exposed_management_ports" // the part that is a shell, a control plane or a database
	propPorts             = "ports"                    // on CONNECTS_TO: the ports one instance reaches the other on
)

// familyPorts is a port set per address family.
type familyPorts struct{ v4, v6 ingestion.PortSet }

// familyFlags is a yes/no per address family.
type familyFlags struct{ v4, v6 bool }

// familyRules is a network ACL's internet entries per address family, in rule order.
type familyRules struct{ v4, v6 []ingestion.FirewallRule }

// netLayer is the optional network layer of a bundle: which route table and NACL each
// subnet uses, which route tables reach an internet gateway and per which family, the
// private egress of those that do not, and each NACL's internet entries.
type netLayer struct {
	subnetRT, subnetNacl map[string]string
	rtIgw                map[string]familyFlags
	rtEgressVia          map[string]string
	nacls                map[string]familyRules
}

// addresses is what an instance can be reached on. known is false for a bundle that does
// not carry instance addressing, which then cannot rule an instance out on it.
type addresses struct{ known, v4, v6 bool }

// internetExposure is what the internet reaches of an instance: the ports its security
// groups open, per family, that also have an address to arrive at, a route through an
// internet gateway and a NACL that lets them through. It returns a note when something
// the groups open is held back - for the UI and the audit. With no address, subnet,
// route or NACL data, the security groups alone decide, so feeds that do not carry the
// network layer degrade gracefully instead of losing every entry point.
func internetExposure(open familyPorts, subnetID string, addr addresses, net netLayer) (ingestion.PortSet, string) {
	exposed := ingestion.PortSet{}
	var notes []string
	for _, f := range []struct {
		name    string
		offered ingestion.PortSet
		address bool
		igw     func(familyFlags) bool
		rules   func(familyRules) []ingestion.FirewallRule
	}{
		{"IPv4", open.v4, addr.v4, func(x familyFlags) bool { return x.v4 }, func(x familyRules) []ingestion.FirewallRule { return x.v4 }},
		{"IPv6", open.v6, addr.v6, func(x familyFlags) bool { return x.v6 }, func(x familyRules) []ingestion.FirewallRule { return x.v6 }},
	} {
		if f.offered.Empty() {
			continue
		}
		if addr.known && !f.address {
			notes = append(notes, "SG-open on "+f.name+" but the instance has no public "+f.name+" address")
			continue
		}
		if rt, known := net.subnetRT[subnetID]; subnetID != "" && known && !f.igw(net.rtIgw[rt]) {
			if via := net.rtEgressVia[rt]; via != "" {
				notes = append(notes, "SG-open but in a private subnet (egress via "+via+", not an internet gateway)")
			} else {
				notes = append(notes, "SG-open but in a private subnet (no internet-gateway route)")
			}
			continue
		}
		allowed := f.offered
		if acl := net.subnetNacl[subnetID]; subnetID != "" && acl != "" {
			if rules, known := net.nacls[acl]; known {
				allowed = ingestion.FirstMatch(f.offered, f.rules(rules))
				if blocked := f.offered.Minus(allowed); !blocked.Empty() {
					if allowed.Empty() {
						notes = append(notes, "SG-open and routed, but the network ACL denies internet ingress")
					} else {
						notes = append(notes, "the network ACL blocks "+blocked.String()+" of what the security groups open")
					}
				}
			}
		}
		exposed = exposed.Union(allowed)
	}
	if !exposed.Empty() && !exposed.Transport() {
		notes = append(notes, "only "+exposed.String()+" reaches it from the internet, which offers no service to attack")
	}
	return exposed, strings.Join(notes, "; ")
}

type builder struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
	// account qualifies the ids of assets whose native identifiers are unique only
	// within one cloud account. Empty for a single-account estate, which keeps the
	// ids this collector has always produced.
	account string
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

// stub creates a placeholder node for something referenced but not described in the
// bundle (a peered VPC, say). Account-scoped like the assets it stands in for: vpc-abc in
// two accounts is two VPCs, and a peering between them is precisely the case where
// merging them would erase the boundary the peering crosses.
func (b *builder) stub(label ontology.Label, name string) string {
	id := ontology.ScopedID(label, b.account, name)
	if _, ok := b.nodes[id]; !ok {
		n := ontology.Node{ID: id, Label: label, Name: name}
		if b.account != "" {
			n.Properties = map[string]any{ontology.PropAccount: b.account}
		}
		b.nodes[id] = n
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
