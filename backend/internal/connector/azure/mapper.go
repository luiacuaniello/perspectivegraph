package azure

import (
	"encoding/json"
	"sort"
	"strings"
)

// azureNetwork is the normalized Azure network state a transport hands the mapper:
// network security groups (the firewall rules), virtual machines (the hosts, with
// their effective NSGs already resolved from the NIC/subnet chain), and VNet
// peerings. It is close to `az network nsg list` / `az vm list -o json`, with the
// VM->NIC->NSG association pre-resolved so the mapper stays a pure shape translation.
type azureNetwork struct {
	NetworkSecurityGroups []azNSG  `json:"networkSecurityGroups"`
	VirtualMachines       []azVM   `json:"virtualMachines"`
	VNetPeerings          []azPeer `json:"vnetPeerings"`
}

type azNSG struct {
	Name          string   `json:"name"`
	SecurityRules []azRule `json:"securityRules"`
}

type azRule struct {
	Name                  string   `json:"name"`
	Direction             string   `json:"direction"` // Inbound | Outbound
	Access                string   `json:"access"`    // Allow | Deny
	SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
	SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	// SourceApplicationSecurityGroups is Azure's east-west micro-segmentation: an
	// inbound rule can admit source *ASGs* rather than CIDRs, and VMs are members of
	// ASGs. This is how a real subscription expresses "the web tier may reach the db
	// tier", so it must survive the mapping - see mapNetworkToCloudnet.
	SourceApplicationSecurityGroups []string `json:"sourceApplicationSecurityGroups"`
}

type azVM struct {
	Name                  string   `json:"name"`
	NetworkSecurityGroups []string `json:"networkSecurityGroups"`
	// ApplicationSecurityGroups are the ASGs this VM belongs to - the membership an
	// NSG rule's SourceApplicationSecurityGroups references to allow east-west traffic.
	ApplicationSecurityGroups []string          `json:"applicationSecurityGroups"`
	Tags                      map[string]string `json:"tags"`
}

type azPeer struct {
	VNet       string `json:"vnet"`
	RemoteVNet string `json:"remoteVnet"`
}

// ── cloudnet input shape (the JSON the existing cloudnet collector parses) ──

type cloudnetBundle struct {
	Provider       string            `json:"provider"`
	SecurityGroups []cnSecurityGroup `json:"security_groups"`
	Instances      []cnInstance      `json:"instances"`
	VpcPeerings    []cnPeering       `json:"vpc_peerings"`
}

type cnSecurityGroup struct {
	GroupID       string           `json:"GroupId"`
	GroupName     string           `json:"GroupName"`
	IpPermissions []cnIpPermission `json:"IpPermissions"`
}

type cnIpPermission struct {
	IpRanges         []cnIpRange         `json:"IpRanges"`
	UserIdGroupPairs []cnUserIdGroupPair `json:"UserIdGroupPairs,omitempty"`
}

type cnIpRange struct {
	CidrIp string `json:"CidrIp"`
}

// cnUserIdGroupPair is cloudnet's SG-to-SG ingress reference: instances in the
// source group can reach instances in the group that admits it. It is the shape
// the collector turns into the discovered lateral-reachability (CONNECTS_TO) edge.
type cnUserIdGroupPair struct {
	GroupID string `json:"GroupId"`
}

type cnSGRef struct {
	GroupID string `json:"GroupId"`
}

type cnInstance struct {
	InstanceID     string    `json:"InstanceId"`
	SecurityGroups []cnSGRef `json:"SecurityGroups"`
	Tags           []cnTag   `json:"Tags,omitempty"`
}

type cnTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type cnPeering struct {
	RequesterVpcInfo cnVpcRef `json:"RequesterVpcInfo"`
	AccepterVpcInfo  cnVpcRef `json:"AccepterVpcInfo"`
}

type cnVpcRef struct {
	VpcID string `json:"VpcId"`
}

// mapNetworkToCloudnet converts normalized Azure network state into the cloudnet
// bundle the existing collector parses (provider "azure"), so identity resolution,
// the graph, and the analyzer run unchanged. An NSG becomes a security group; its
// inbound Allow rules become ingress - CIDR sources become IpRanges (Azure's
// "Internet"/"*"/"Any" service tags map to 0.0.0.0/0, so cloudnet flags exposure as
// it does an AWS 0.0.0.0/0 SG) and *ASG* sources become UserIdGroupPairs, the SG-to-SG
// reference cloudnet turns into the east-west CONNECTS_TO edge. A VM becomes an
// instance bound to its NSGs *and its ASGs* (so a rule that admits an ASG connects
// that ASG's members), and a VNet peering becomes a peering. Without the ASG mapping
// the exposed tier would dead-end and no internet -> crown-jewel path would form.
// Deterministic output (sorted tags) so a re-pull is byte-stable.
func mapNetworkToCloudnet(raw []byte) ([]byte, error) {
	var in azureNetwork
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	b := cloudnetBundle{Provider: "azure"}

	for _, nsg := range in.NetworkSecurityGroups {
		sg := cnSecurityGroup{GroupID: nsg.Name, GroupName: nsg.Name}
		for _, r := range nsg.SecurityRules {
			if !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Access, "Allow") {
				continue
			}
			perm := cnIpPermission{}
			for _, cidr := range sourceCidrs(r) {
				perm.IpRanges = append(perm.IpRanges, cnIpRange{CidrIp: cidr})
			}
			for _, asg := range r.SourceApplicationSecurityGroups {
				if asg != "" {
					perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, cnUserIdGroupPair{GroupID: asgGroupID(asg)})
				}
			}
			if len(perm.IpRanges) > 0 || len(perm.UserIdGroupPairs) > 0 {
				sg.IpPermissions = append(sg.IpPermissions, perm)
			}
		}
		b.SecurityGroups = append(b.SecurityGroups, sg)
	}

	for _, vm := range in.VirtualMachines {
		inst := cnInstance{InstanceID: vm.Name}
		for _, nsg := range vm.NetworkSecurityGroups {
			inst.SecurityGroups = append(inst.SecurityGroups, cnSGRef{GroupID: nsg})
		}
		for _, asg := range vm.ApplicationSecurityGroups {
			inst.SecurityGroups = append(inst.SecurityGroups, cnSGRef{GroupID: asgGroupID(asg)})
		}
		for _, k := range sortedKeys(vm.Tags) {
			inst.Tags = append(inst.Tags, cnTag{Key: k, Value: vm.Tags[k]})
		}
		b.Instances = append(b.Instances, inst)
	}

	for _, p := range in.VNetPeerings {
		b.VpcPeerings = append(b.VpcPeerings, cnPeering{
			RequesterVpcInfo: cnVpcRef{VpcID: p.VNet},
			AccepterVpcInfo:  cnVpcRef{VpcID: p.RemoteVNet},
		})
	}
	return json.Marshal(b)
}

// sourceCidrs normalizes an inbound rule's source(s) to CIDRs, mapping Azure's
// "any source" service tags to 0.0.0.0/0 so the collector flags internet exposure.
func sourceCidrs(r azRule) []string {
	raw := append([]string(nil), r.SourceAddressPrefixes...)
	if r.SourceAddressPrefix != "" {
		raw = append(raw, r.SourceAddressPrefix)
	}
	var out []string
	for _, s := range raw {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "internet", "*", "any", "0.0.0.0/0":
			out = append(out, "0.0.0.0/0")
		default:
			out = append(out, s)
		}
	}
	return out
}

// asgGroupID namespaces an application-security-group name into the cloudnet group
// id space so it can't collide with an NSG that happens to share the name (both
// become cloudnet "security groups", but they are distinct membership sets).
func asgGroupID(name string) string { return "asg/" + name }

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
