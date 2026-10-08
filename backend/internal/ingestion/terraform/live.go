package terraform

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A plan describes the network its configuration manages, and a security group is shared
// by whatever uses it. A rule the plan adds to a group reaches every instance in the group,
// including the ones launched elsewhere - by another configuration, an Auto Scaling group,
// a console - and an instance the plan puts in a group is admitted by whatever the group
// admits, including the rules written elsewhere. Neither is in the plan.
//
// With a live read of the account, the plan's network is laid over the account's and the
// whole is judged as one, by the same collector that judges the account: the instances
// that use a group the plan opens are exposed, or not, by their own subnets and addresses.
// Without one, what the plan opens of a group it did not create, and the rules of a group
// it uses but does not hold, are listed as outside the plan: a route through them can be
// neither found nor ruled out.

// readLive decodes the account's network feed, as a live read fetched it.
func readLive(raw []byte) (*netBundle, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var b netBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("the account's network feed: %w", err)
	}
	return &b, nil
}

// overlay is a view of the plan's network laid over the account's. Rules and routes add
// to what the account already has: a plan that removes one closes nothing here, which the
// gate, asking only what a change opens, does not need. An instance the plan describes is
// as the plan describes it; one it does not, as the account does.
func overlay(live, plan netBundle) netBundle {
	out := live
	out.described, out.address = plan.described, plan.address

	out.SecurityGroups = append([]sgRecord(nil), live.SecurityGroups...)
	groups := map[string]int{}
	for i, g := range out.SecurityGroups {
		groups[g.GroupID] = i
	}
	for _, g := range plan.SecurityGroups {
		i, ok := groups[g.GroupID]
		if !ok {
			groups[g.GroupID] = len(out.SecurityGroups)
			out.SecurityGroups = append(out.SecurityGroups, g)
			continue
		}
		merged := out.SecurityGroups[i]
		merged.IpPermissions = append(append([]ipPermission(nil), merged.IpPermissions...), g.IpPermissions...)
		out.SecurityGroups[i] = merged
	}

	planned := map[string]bool{}
	for _, inst := range plan.Instances {
		planned[inst.InstanceID] = true
	}
	out.Instances = nil
	for _, inst := range live.Instances {
		if !planned[inst.InstanceID] {
			out.Instances = append(out.Instances, inst)
		}
	}
	out.Instances = append(out.Instances, plan.Instances...)

	out.Subnets = append([]subnetRecord(nil), live.Subnets...)
	subnets := map[string]int{}
	for i, sn := range out.Subnets {
		subnets[sn.SubnetID] = i
	}
	for _, sn := range plan.Subnets {
		i, ok := subnets[sn.SubnetID]
		if !ok {
			subnets[sn.SubnetID] = len(out.Subnets)
			out.Subnets = append(out.Subnets, sn)
			continue
		}
		// The plan says which table a subnet uses when it manages the association; the
		// account says the rest, its network ACL among it.
		if sn.RouteTableID != "" {
			out.Subnets[i].RouteTableID = sn.RouteTableID
		}
	}

	out.RouteTables = append([]rtRecord(nil), live.RouteTables...)
	tables := map[string]int{}
	for i, t := range out.RouteTables {
		tables[t.RouteTableID] = i
	}
	for _, t := range plan.RouteTables {
		i, ok := tables[t.RouteTableID]
		if !ok {
			tables[t.RouteTableID] = len(out.RouteTables)
			out.RouteTables = append(out.RouteTables, t)
			continue
		}
		merged := out.RouteTables[i]
		merged.Routes = append(append([]route(nil), merged.Routes...), t.Routes...)
		out.RouteTables[i] = merged
	}

	out.InstanceProfiles = append([]profileRecord(nil), live.InstanceProfiles...)
	profiles := map[string]int{}
	for i, pr := range out.InstanceProfiles {
		profiles[pr.Arn] = i
	}
	for _, pr := range plan.InstanceProfiles {
		if i, ok := profiles[pr.Arn]; ok {
			out.InstanceProfiles[i] = pr
			continue
		}
		out.InstanceProfiles = append(out.InstanceProfiles, pr)
	}
	return out
}

// admits is what a security group admits: from the internet, per address family, and from
// other groups.
type admits struct {
	v4, v6 ingestion.PortSet
	from   map[string]ingestion.PortSet
}

// admitted reads what each group of a view admits, as cloudnet reads it: 0.0.0.0/0 and ::/0
// are the internet, a group pair is that group's instances.
func admitted(b netBundle) map[string]admits {
	out := map[string]admits{}
	for _, g := range b.SecurityGroups {
		gr := out[g.GroupID]
		if gr.from == nil {
			gr.from = map[string]ingestion.PortSet{}
		}
		for _, perm := range g.IpPermissions {
			ports := ingestion.RulePorts(perm.IpProtocol, perm.FromPort, perm.ToPort)
			for _, c := range perm.IpRanges {
				switch c.CidrIp {
				case "0.0.0.0/0":
					gr.v4 = gr.v4.Union(ports)
				case "::/0":
					gr.v6 = gr.v6.Union(ports)
				}
			}
			for _, c := range perm.Ipv6Ranges {
				if c.CidrIpv6 == "::/0" {
					gr.v6 = gr.v6.Union(ports)
				}
			}
			for _, pair := range perm.UserIdGroupPairs {
				if pair.GroupID != "" {
					gr.from[pair.GroupID] = gr.from[pair.GroupID].Union(ports)
				}
			}
		}
		out[g.GroupID] = gr
	}
	return out
}

// outside lists what the plan's network reaches but does not describe, and the account -
// when it was read - does not either:
//
//   - a group the plan did not create, which it opens further: to the internet or to
//     another group. Instances the plan does not describe may use it.
//   - a group the plan did not create, which it lets into another: instances the plan
//     does not describe may be in it.
//   - a group the plan does not hold, used by an instance whose exposure the plan changes:
//     the group's rules are written elsewhere.
//   - a route table or a subnet the plan did not create, which it routes to the internet:
//     instances the plan does not describe may be behind it.
//
// What the live read holds is not listed: laid over the account, the plan meets its
// instances and rules there. Only what the plan changes counts, so a plan that leaves a
// group or a route as it was lists nothing for it.
func outside(prior, planned netBundle, live *netBundle) []string {
	inLive := map[string]bool{}
	if live != nil {
		for _, g := range live.SecurityGroups {
			inLive[g.GroupID] = true
		}
		for _, sn := range live.Subnets {
			inLive[sn.SubnetID] = true
		}
		for _, t := range live.RouteTables {
			inLive[t.RouteTableID] = true
		}
	}
	unseen := func(id string) bool { return !IsPlaceholder(id) && !inLive[id] }
	whyAs := func(kind, id, what, users string) string {
		if live != nil {
			return kind + " " + id + " " + what + ", and the account read live does not hold it"
		}
		return kind + " " + id + " " + what + ", and " + users
	}
	why := func(group, what string) string {
		return whyAs("security group", group, what, "what the plan does not describe - an instance, a load balancer - may use it")
	}

	var notes []string
	was, now := admitted(prior), admitted(planned)
	ids := make([]string, 0, len(now))
	for id := range now {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		gr, old := now[id], was[id]
		if opened := gr.v4.Minus(old.v4).Union(gr.v6.Minus(old.v6)); opened.Transport() && unseen(id) {
			notes = append(notes, why(id, "is opened to the internet on "+opened.String()))
		}
		srcs := make([]string, 0, len(gr.from))
		for src := range gr.from {
			srcs = append(srcs, src)
		}
		sort.Strings(srcs)
		for _, src := range srcs {
			added := gr.from[src].Minus(old.from[src])
			if !added.Transport() {
				continue
			}
			if unseen(id) {
				notes = append(notes, why(id, "is opened to "+src+" on "+added.String()))
			}
			if src != id && unseen(src) {
				notes = append(notes, why(src, "is let into "+id+" on "+added.String()))
			}
		}
	}

	wasTables, wasSubnets := routedToInternet(prior)
	nowTables, nowSubnets := routedToInternet(planned)
	for _, id := range sortedKeys(nowTables) {
		if !wasTables[id] && unseen(id) {
			notes = append(notes, whyAs("route table", id, "is given a route to the internet", "subnets the plan does not describe may use it"))
		}
	}
	for _, id := range sortedKeys(nowSubnets) {
		if !wasSubnets[id] && unseen(id) {
			notes = append(notes, whyAs("subnet", id, "is routed to the internet", "instances the plan does not describe may be in it"))
		}
	}

	same := map[string]bool{}
	for _, id := range unchangedExposure(prior, planned) {
		same[id] = true
	}
	holds := "the configuration does not hold"
	if live != nil {
		holds = "neither the configuration nor the account read live holds"
	}
	for _, inst := range planned.Instances {
		if same[inst.InstanceID] {
			continue
		}
		for _, g := range inst.SecurityGroups {
			if !planned.described[g.GroupID] && unseen(g.GroupID) {
				notes = append(notes, planned.address[inst.InstanceID]+": its security group "+g.GroupID+" has rules "+holds)
			}
		}
	}
	return dedupe(notes)
}

// routedToInternet lists the route tables of a view with a default route through an
// internet gateway, and the subnets that use one.
func routedToInternet(b netBundle) (tables, subnets map[string]bool) {
	tables, subnets = map[string]bool{}, map[string]bool{}
	for _, t := range b.RouteTables {
		for _, r := range t.Routes {
			if strings.HasPrefix(r.GatewayID, "igw-") && (r.DestinationCidrBlock == "0.0.0.0/0" || r.DestinationIpv6CidrBlock == "::/0") {
				tables[t.RouteTableID] = true
			}
		}
	}
	for _, sn := range b.Subnets {
		if tables[sn.RouteTableID] {
			subnets[sn.SubnetID] = true
		}
	}
	return tables, subnets
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// changedNodes are the assets whose reachability a view of the network changes: the ones
// whose exposure differs between the two, and the ones a new network route leads to. A
// rule added to a group outside the configuration changes the instances in the group, and
// those are what the change is judged by.
func changedNodes(before, after []ontology.Event) map[string]bool {
	out := map[string]bool{}
	was := map[string]string{}
	edges := map[string]bool{}
	for _, ev := range before {
		for _, n := range ev.Nodes {
			was[n.ID] = exposureOf(n.Properties)
		}
		for _, e := range ev.Edges {
			edges[string(e.Type)+"\x00"+e.From+"\x00"+e.To] = true
		}
	}
	for _, ev := range after {
		for _, n := range ev.Nodes {
			if fp, ok := was[n.ID]; ok && fp != exposureOf(n.Properties) {
				out[n.ID] = true
			}
		}
		for _, e := range ev.Edges {
			if networkEdge[e.Type] && !edges[string(e.Type)+"\x00"+e.From+"\x00"+e.To] {
				out[e.To] = true
			}
		}
	}
	return out
}

// networkEdge are the edges the network feed draws: one instance reaching another, a load
// balancer reaching its targets.
var networkEdge = map[ontology.EdgeType]bool{ontology.EdgeConnectsTo: true, ontology.EdgeRoutesTo: true}

// exposureOf is a node's exposure, in one comparable string.
func exposureOf(props map[string]any) string {
	var b strings.Builder
	for _, k := range exposureProps {
		fmt.Fprintf(&b, "%s=%v;", k, props[k])
	}
	return b.String()
}
