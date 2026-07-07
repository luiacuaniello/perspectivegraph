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
}

type azVM struct {
	Name                  string            `json:"name"`
	NetworkSecurityGroups []string          `json:"networkSecurityGroups"`
	Tags                  map[string]string `json:"tags"`
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
	IpRanges []cnIpRange `json:"IpRanges"`
}

type cnIpRange struct {
	CidrIp string `json:"CidrIp"`
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
// the graph, and the analyzer run unchanged. An NSG becomes a security group whose
// inbound Allow rules become ingress CIDRs - Azure's "Internet"/"*"/"Any" service
// tags map to 0.0.0.0/0, so cloudnet flags the exposure exactly as it does for an
// AWS 0.0.0.0/0 SG; a VM becomes an instance bound to its NSGs; a VNet peering
// becomes a peering. Deterministic output (sorted tags) so a re-pull is byte-stable.
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
			if len(perm.IpRanges) > 0 {
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

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
