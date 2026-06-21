// Package cloudnet discovers cloud network reachability — who can reach whom —
// from security groups, instances and VPC peerings, and emits it as ontology
// relationships. It answers the lateral-movement question scanners can't:
//
//	0.0.0.0/0 ingress     → the instance is internet_exposed (a path seed)
//	SG-to-SG ingress rule → instances in the source SG ──CONNECTS_TO──▶ instances in the target SG
//	VPC peering           → VPC ──CONNECTS_TO──▶ VPC
//
// Input is a bundle of real AWS shapes (describe-security-groups /
// describe-instances / describe-vpc-peering-connections). Crown-jewel
// classification is tag-driven (ingestion.CrownJewelFromTags).
package cloudnet

import (
	"encoding/json"
	"fmt"
	"io"
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
		SecurityGroups []struct {
			GroupID string `json:"GroupId"`
		} `json:"SecurityGroups"`
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	} `json:"instances"`
	VPCPeerings []struct {
		RequesterVpcInfo struct {
			VpcID string `json:"VpcId"`
		} `json:"RequesterVpcInfo"`
		AccepterVpcInfo struct {
			VpcID string `json:"VpcId"`
		} `json:"AccepterVpcInfo"`
	} `json:"vpc_peerings"`
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
		for _, sg := range inst.SecurityGroups {
			instancesBySG[sg.GroupID] = append(instancesBySG[sg.GroupID], id)
			if sgInternet[sg.GroupID] {
				props[ontology.PropInternetExposed] = true
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
