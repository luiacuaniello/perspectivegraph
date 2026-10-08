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

// The feeds a live read hands over, by name: the network and API Gateway.
const (
	feedNetwork    = "cloudnet"
	feedAPIGateway = "apigateway"
)

// liveState is the account as a live read fetched it: its network, and its APIs.
type liveState struct {
	net *netBundle
	api *apiBundle
}

// readLive decodes the account's feeds, as a live read fetched them.
func readLive(feeds map[string][]byte) (*liveState, error) {
	var l liveState
	if raw := feeds[feedNetwork]; len(raw) > 0 {
		var b netBundle
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("the account's network feed: %w", err)
		}
		l.net = &b
	}
	if raw := feeds[feedAPIGateway]; len(raw) > 0 {
		var b apiBundle
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("the account's API Gateway feed: %w", err)
		}
		l.api = &b
	}
	if l.net == nil && l.api == nil {
		return nil, nil
	}
	return &l, nil
}

// layOver judges a state of the plan laid over the account. An asset the plan held only in
// part - a load balancer it adds a listener to, an API it adds a route to - is whole once
// the account's record of it is there, and no longer partial.
func (p *Plan) layOver(b *bundles, l *liveState, dropped map[string][]entryKey) {
	if l.net != nil {
		b.view = overlay(*l.net, b.net, dropped)
		for _, lb := range l.net.LoadBalancers {
			delete(b.partial, ingestion.LoadBalancerID(p.Account, lb.LoadBalancerArn, lb.LoadBalancerName))
		}
	}
	if l.api != nil {
		b.apiView = overlayAPI(*l.api, b.api)
		for _, region := range []string{b.api.Region, b.apiView.Region} {
			for _, id := range liveAPIIDs(*l.api) {
				delete(b.partial, ingestion.RegionalID(ontology.LabelAPI, p.Account, region, id))
			}
		}
	}
}

// entryKey names a network ACL entry: AWS keeps one per rule number and direction.
type entryKey struct {
	egress bool
	number int
}

// droppedACLEntries are the network ACL rules the plan deletes: rule resources in the state
// it starts from that the state it leads to does not have. Laid over the account, they go.
func (p *Plan) droppedACLEntries() map[string][]entryKey {
	out := map[string][]entryKey{}
	for _, r := range p.Resources(Prior, "aws_network_acl_rule") {
		if !r.Managed() {
			continue
		}
		if now := p.byAddr[Planned][r.Address]; now != nil && now.Values["rule_number"] == r.Values["rule_number"] &&
			now.Values["egress"] == r.Values["egress"] && p.Str(Planned, now, "network_acl_id") == p.Str(Prior, r, "network_acl_id") {
			continue
		}
		n, ok := toInt(r.Values["rule_number"])
		acl := p.Str(Prior, r, "network_acl_id")
		if !ok || acl == "" {
			continue
		}
		egress, _ := r.Values["egress"].(bool)
		out[acl] = append(out[acl], entryKey{egress, n})
	}
	return out
}

// overlay is a view of the plan's network laid over the account's. Security group rules
// and routes add to what the account already has: a plan that removes one closes nothing
// here, which the gate, asking only what a change opens, does not need. A network ACL is
// first-match, so there an entry the plan writes replaces the account's of its number, and
// one it deletes goes. An instance, load balancer or ECS service the plan describes is as
// the plan describes it - a target group keeping the targets the account registered in it
// - and one it does not, as the account does.
func overlay(live, plan netBundle, dropped map[string][]entryKey) netBundle {
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
		// The plan says which table and ACL a subnet uses when it manages the association;
		// the account says the rest.
		if sn.RouteTableID != "" {
			out.Subnets[i].RouteTableID = sn.RouteTableID
		}
		if sn.NetworkACLID != "" {
			out.Subnets[i].NetworkACLID = sn.NetworkACLID
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

	out.NetworkACLs = make([]naclRecord, len(live.NetworkACLs))
	acls := map[string]int{}
	for i, a := range live.NetworkACLs {
		out.NetworkACLs[i] = naclRecord{NetworkACLID: a.NetworkACLID, Entries: append([]naclEntry(nil), a.Entries...)}
		acls[a.NetworkACLID] = i
	}
	for _, a := range plan.NetworkACLs {
		i, ok := acls[a.NetworkACLID]
		switch {
		case !ok:
			acls[a.NetworkACLID] = len(out.NetworkACLs)
			out.NetworkACLs = append(out.NetworkACLs, naclRecord{NetworkACLID: a.NetworkACLID, Entries: append([]naclEntry(nil), a.Entries...)})
		case plan.described[a.NetworkACLID]:
			out.NetworkACLs[i].Entries = append([]naclEntry(nil), a.Entries...)
		default:
			l := newEntryList(out.NetworkACLs[i].Entries)
			for _, e := range a.Entries {
				l.set(e)
			}
			out.NetworkACLs[i].Entries = l.list()
		}
	}
	for acl, keys := range dropped {
		i, ok := acls[acl]
		if !ok || plan.described[acl] {
			continue
		}
		var kept []naclEntry
		for _, e := range out.NetworkACLs[i].Entries {
			gone := false
			for _, k := range keys {
				gone = gone || (k == entryKey{e.Egress, e.RuleNumber} && !planHasEntry(plan, acl, k))
			}
			if !gone {
				kept = append(kept, e)
			}
		}
		out.NetworkACLs[i].Entries = kept
	}

	// The account's targets of each group: an Auto Scaling group registers its instances,
	// an ECS service its tasks, and neither is in the plan.
	liveTargets := map[string][]target{}
	out.LoadBalancers = make([]lbRecord, len(live.LoadBalancers))
	lbs := map[string]int{}
	for i, l := range live.LoadBalancers {
		out.LoadBalancers[i] = copyLB(l)
		lbs[l.LoadBalancerArn] = i
		for _, g := range l.TargetGroups {
			liveTargets[g.TargetGroupArn] = append(liveTargets[g.TargetGroupArn], g.Targets...)
		}
	}
	for _, l := range plan.LoadBalancers {
		merged := copyLB(l)
		for gi, g := range merged.TargetGroups {
			merged.TargetGroups[gi].Targets = unionTargets(liveTargets[g.TargetGroupArn], g.Targets)
		}
		i, ok := lbs[l.LoadBalancerArn]
		switch {
		case !ok:
			lbs[l.LoadBalancerArn] = len(out.LoadBalancers)
			out.LoadBalancers = append(out.LoadBalancers, merged)
		case plan.described[l.LoadBalancerArn]:
			out.LoadBalancers[i] = merged
		default:
			// Listeners and target groups added to a load balancer the configuration does
			// not manage: the account says what it is.
			cur := &out.LoadBalancers[i]
			cur.Listeners = append(cur.Listeners, merged.Listeners...)
			mergeGroups(cur, merged.TargetGroups)
		}
	}
	if len(plan.looseGroups) > 0 {
		loose := map[string][]target{}
		for _, g := range plan.looseGroups {
			loose[g.TargetGroupArn] = append(loose[g.TargetGroupArn], g.Targets...)
		}
		for i := range out.LoadBalancers {
			for gi := range out.LoadBalancers[i].TargetGroups {
				if t := &out.LoadBalancers[i].TargetGroups[gi]; loose[t.TargetGroupArn] != nil {
					t.Targets = unionTargets(t.Targets, loose[t.TargetGroupArn])
				}
			}
		}
	}

	out.ECSServices = append([]ecsRecord(nil), live.ECSServices...)
	services := map[string]int{}
	for i, svc := range out.ECSServices {
		services[svc.ServiceArn] = i
	}
	for _, svc := range plan.ECSServices {
		i, ok := services[svc.ServiceArn]
		if !ok {
			out.ECSServices = append(out.ECSServices, svc)
			continue
		}
		if svc.TaskRoleArn == "" {
			// A task definition outside the plan: the account knows its role.
			svc.TaskRoleArn = out.ECSServices[i].TaskRoleArn
		}
		out.ECSServices[i] = svc
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

func planHasEntry(plan netBundle, acl string, k entryKey) bool {
	for _, a := range plan.NetworkACLs {
		if a.NetworkACLID != acl {
			continue
		}
		for _, e := range a.Entries {
			if (entryKey{e.Egress, e.RuleNumber}) == k {
				return true
			}
		}
	}
	return false
}

func copyLB(l lbRecord) lbRecord {
	l.SecurityGroups = append([]string(nil), l.SecurityGroups...)
	l.AvailabilityZones = append([]lbZone(nil), l.AvailabilityZones...)
	l.Listeners = append([]listener(nil), l.Listeners...)
	groups := make([]tgRecord, len(l.TargetGroups))
	for i, g := range l.TargetGroups {
		g.Targets = append([]target(nil), g.Targets...)
		groups[i] = g
	}
	l.TargetGroups = groups
	return l
}

// mergeGroups puts target groups into a load balancer's: a group's targets join the
// group's own when the load balancer already forwards to it.
func mergeGroups(lb *lbRecord, groups []tgRecord) {
	at := map[string]int{}
	for i, g := range lb.TargetGroups {
		at[g.TargetGroupArn] = i
	}
	for _, g := range groups {
		if i, ok := at[g.TargetGroupArn]; ok {
			lb.TargetGroups[i].Targets = unionTargets(lb.TargetGroups[i].Targets, g.Targets)
			continue
		}
		at[g.TargetGroupArn] = len(lb.TargetGroups)
		lb.TargetGroups = append(lb.TargetGroups, g)
	}
}

func unionTargets(a, b []target) []target {
	out := append([]target(nil), a...)
	seen := map[string]bool{}
	for _, t := range a {
		seen[fmt.Sprint(t.ID, "\x00", t.Port)] = true
	}
	for _, t := range b {
		if k := fmt.Sprint(t.ID, "\x00", t.Port); !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	if out == nil {
		out = []target{}
	}
	return out
}

// overlayAPI lays the plan's APIs over the account's: a method or route the plan writes
// replaces the account's of its path or key, its stages join the API's, and an API the
// configuration defines takes its name, endpoint and policy from it.
func overlayAPI(live, plan apiBundle) apiBundle {
	out := apiBundle{Account: live.Account, Region: live.Region, described: plan.described}
	if out.Account == "" {
		out.Account = plan.Account
	}
	if out.Region == "" {
		out.Region = plan.Region
	}
	rest := map[string]int{}
	for _, a := range live.RestAPIs {
		a.Stages = append([]string{}, a.Stages...)
		a.Methods = append([]restMethod{}, a.Methods...)
		rest[a.ID] = len(out.RestAPIs)
		out.RestAPIs = append(out.RestAPIs, a)
	}
	for _, a := range plan.RestAPIs {
		i, ok := rest[a.ID]
		if !ok {
			out.RestAPIs = append(out.RestAPIs, a)
			continue
		}
		cur := &out.RestAPIs[i]
		if plan.described[a.ID] {
			cur.Name, cur.EndpointTypes, cur.DisableExecuteAPIEndpoint = a.Name, a.EndpointTypes, a.DisableExecuteAPIEndpoint
			if a.Policy != nil {
				cur.Policy = a.Policy
			}
		}
		cur.Stages = unionStrings(cur.Stages, a.Stages)
		at := map[string]int{}
		for j, m := range cur.Methods {
			at[m.Path+" "+strings.ToUpper(m.HTTPMethod)] = j
		}
		for _, m := range a.Methods {
			k := m.Path + " " + strings.ToUpper(m.HTTPMethod)
			if j, ok := at[k]; ok {
				cur.Methods[j] = m
				continue
			}
			at[k] = len(cur.Methods)
			cur.Methods = append(cur.Methods, m)
		}
	}
	httpAPIs := map[string]int{}
	for _, a := range live.HTTPAPIs {
		a.Stages = append([]string{}, a.Stages...)
		a.Routes = append([]httpRoute{}, a.Routes...)
		a.Integrations = append([]httpIntegration{}, a.Integrations...)
		httpAPIs[a.APIID] = len(out.HTTPAPIs)
		out.HTTPAPIs = append(out.HTTPAPIs, a)
	}
	for _, a := range plan.HTTPAPIs {
		i, ok := httpAPIs[a.APIID]
		if !ok {
			out.HTTPAPIs = append(out.HTTPAPIs, a)
			continue
		}
		cur := &out.HTTPAPIs[i]
		if plan.described[a.APIID] {
			cur.Name, cur.ProtocolType, cur.DisableExecuteAPIEndpoint = a.Name, a.ProtocolType, a.DisableExecuteAPIEndpoint
		}
		cur.Stages = unionStrings(cur.Stages, a.Stages)
		routes := map[string]int{}
		for j, rt := range cur.Routes {
			routes[rt.RouteKey] = j
		}
		for _, rt := range a.Routes {
			if j, ok := routes[rt.RouteKey]; ok {
				cur.Routes[j] = rt
				continue
			}
			routes[rt.RouteKey] = len(cur.Routes)
			cur.Routes = append(cur.Routes, rt)
		}
		integrations := map[string]int{}
		for j, in := range cur.Integrations {
			integrations[in.IntegrationID] = j
		}
		for _, in := range a.Integrations {
			if j, ok := integrations[in.IntegrationID]; ok {
				cur.Integrations[j] = in
				continue
			}
			integrations[in.IntegrationID] = len(cur.Integrations)
			cur.Integrations = append(cur.Integrations, in)
		}
	}
	if out.RestAPIs == nil {
		out.RestAPIs = []restAPIRecord{}
	}
	if out.HTTPAPIs == nil {
		out.HTTPAPIs = []httpAPIRecord{}
	}
	return out
}

// unionStrings is a, then what of b it does not hold.
func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			a = append(a, s)
		}
	}
	return a
}

func liveAPIIDs(b apiBundle) []string {
	var out []string
	for _, a := range b.RestAPIs {
		out = append(out, a.ID)
	}
	for _, a := range b.HTTPAPIs {
		out = append(out, a.APIID)
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

// outside lists what the plan reaches but does not describe, and the account - when it
// was read - does not either:
//
//   - a security group the plan did not create, which it opens further: to the internet or
//     to another group. What the plan does not describe may use it.
//   - a group the plan did not create, which it lets into another: instances the plan
//     does not describe may be in it.
//   - a group the plan does not hold, used by an instance, load balancer or ECS service the
//     plan adds or changes: the group's rules are written elsewhere.
//   - a route table, subnet or network ACL the plan did not create, which it opens to the
//     internet: what the plan does not describe may be behind it.
//   - a load balancer or API the plan adds a listener, target group or open route to,
//     without describing it - its scheme, subnets, stages or policy.
//   - targets added to a group no load balancer of the plan forwards to, and an ECS
//     service whose task definition, and so its role, is defined elsewhere.
//
// What the live read holds is not listed: laid over the account, the plan meets it there.
// Only what the plan changes counts, so a plan that leaves these as they were lists nothing.
func outside(prior, planned bundles, live *liveState) []string {
	inLive := map[string]bool{}
	if live != nil && live.net != nil {
		for _, g := range live.net.SecurityGroups {
			inLive[g.GroupID] = true
		}
		for _, sn := range live.net.Subnets {
			inLive[sn.SubnetID] = true
		}
		for _, t := range live.net.RouteTables {
			inLive[t.RouteTableID] = true
		}
		for _, a := range live.net.NetworkACLs {
			inLive[a.NetworkACLID] = true
		}
		for _, lb := range live.net.LoadBalancers {
			inLive[lb.LoadBalancerArn] = true
			for _, g := range lb.TargetGroups {
				inLive[g.TargetGroupArn] = true
			}
		}
		for _, svc := range live.net.ECSServices {
			inLive[svc.ServiceArn] = true
		}
	}
	if live != nil && live.api != nil {
		for _, id := range liveAPIIDs(*live.api) {
			inLive[id] = true
		}
	}
	read := live != nil
	unseen := func(id string) bool { return !IsPlaceholder(id) && !inLive[id] }
	whyAs := func(kind, id, what, users string) string {
		if read {
			return kind + " " + id + " " + what + ", and the account read live does not hold it"
		}
		return kind + " " + id + " " + what + ", and " + users
	}
	why := func(group, what string) string {
		return whyAs("security group", group, what, "what the plan does not describe - an instance, a load balancer - may use it")
	}
	was, now := prior.net, planned.net

	var notes []string
	before, after := admitted(was), admitted(now)
	for _, id := range sortedKeys(keysOfAdmits(after)) {
		gr, old := after[id], before[id]
		if opened := gr.v4.Minus(old.v4).Union(gr.v6.Minus(old.v6)); opened.Transport() && unseen(id) {
			notes = append(notes, why(id, "is opened to the internet on "+opened.String()))
		}
		for _, src := range sortedKeys(keysOfPorts(gr.from)) {
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

	wasTables, wasSubnets := routedToInternet(was)
	nowTables, nowSubnets := routedToInternet(now)
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

	// Network ACLs that let in more than they did, and subnets put under another ACL.
	wasACL := map[string]naclRecord{}
	for _, a := range was.NetworkACLs {
		wasACL[a.NetworkACLID] = a
	}
	nowACL := map[string]naclRecord{}
	for _, a := range now.NetworkACLs {
		nowACL[a.NetworkACLID] = a
		o4, o6 := aclAdmits(wasACL[a.NetworkACLID])
		n4, n6 := aclAdmits(a)
		if more := n4.Minus(o4).Union(n6.Minus(o6)); more.Transport() && unseen(a.NetworkACLID) {
			notes = append(notes, whyAs("network ACL", a.NetworkACLID, "lets in more from the internet ("+more.String()+")",
				"subnets the plan does not describe may use it"))
		}
	}
	wasSubnetACL := map[string]string{}
	for _, sn := range was.Subnets {
		wasSubnetACL[sn.SubnetID] = sn.NetworkACLID
	}
	for _, sn := range now.Subnets {
		if sn.NetworkACLID == "" || sn.NetworkACLID == wasSubnetACL[sn.SubnetID] || !unseen(sn.SubnetID) {
			continue
		}
		if a, ok := nowACL[sn.NetworkACLID]; ok {
			if v4, v6 := aclAdmits(a); !v4.Union(v6).Transport() {
				continue // an ACL that lets nothing in opens nothing
			}
		}
		notes = append(notes, whyAs("subnet", sn.SubnetID, "is put under network ACL "+sn.NetworkACLID,
			"instances the plan does not describe may be in it"))
	}

	// What the plan adds or changes, in groups whose rules are elsewhere.
	holds := "the configuration does not hold"
	if read {
		holds = "neither the configuration nor the account read live holds"
	}
	member := func(who string, groups []string) {
		for _, g := range groups {
			if !now.described[g] && unseen(g) {
				notes = append(notes, who+": its security group "+g+" has rules "+holds)
			}
		}
	}
	same := map[string]bool{}
	for _, id := range unchangedExposure(was, now) {
		same[id] = true
	}
	for _, inst := range now.Instances {
		if !same[inst.InstanceID] {
			var groups []string
			for _, g := range inst.SecurityGroups {
				groups = append(groups, g.GroupID)
			}
			member(now.address[inst.InstanceID], groups)
		}
	}
	wasLB := map[string]string{}
	for _, lb := range was.LoadBalancers {
		wasLB[lb.LoadBalancerArn] = fingerprint(lb)
	}
	for _, lb := range now.LoadBalancers {
		if wasLB[lb.LoadBalancerArn] == fingerprint(lb) {
			continue
		}
		name := "load balancer " + lb.LoadBalancerName
		if now.described[lb.LoadBalancerArn] {
			member(name, lb.SecurityGroups)
			continue
		}
		if unseen(lb.LoadBalancerArn) {
			notes = append(notes, whyAs("load balancer", lb.LoadBalancerName, "gets a listener or a target group",
				"the plan does not describe its scheme, subnets or security groups"))
		}
	}
	wasSvc := map[string]string{}
	for _, svc := range was.ECSServices {
		wasSvc[svc.ServiceArn] = fingerprint(svc)
	}
	for _, svc := range now.ECSServices {
		if wasSvc[svc.ServiceArn] != fingerprint(svc) {
			member("ECS service "+svc.ServiceName, svc.SecurityGroups)
		}
	}
	wasTask := map[string]bool{}
	for _, t := range was.unknownTask {
		wasTask[t] = true
	}
	for _, t := range now.unknownTask {
		parts := strings.SplitN(t, "\x00", 3)
		if wasTask[t] || len(parts) < 3 || inLive[parts[1]] {
			continue
		}
		notes = append(notes, parts[0]+": its task definition "+parts[2]+" is outside the plan, so the role its tasks hold is not known")
	}
	wasLoose := map[string]bool{}
	for _, g := range was.looseGroups {
		for _, t := range g.Targets {
			wasLoose[g.TargetGroupArn+"\x00"+t.ID] = true
		}
	}
	for _, g := range now.looseGroups {
		for _, t := range g.Targets {
			if !wasLoose[g.TargetGroupArn+"\x00"+t.ID] && unseen(g.TargetGroupArn) {
				notes = append(notes, whyAs("target group", g.TargetGroupArn, "gains target "+t.ID,
					"the load balancer that forwards to it is not in the plan"))
			}
		}
	}

	// Routes that ask for nothing, added to APIs the configuration does not define.
	wasRoutes := map[string]bool{}
	for _, k := range openRoutes(prior.api) {
		wasRoutes[k[0]+"\x00"+k[1]] = true
	}
	for _, k := range openRoutes(planned.api) {
		if !wasRoutes[k[0]+"\x00"+k[1]] && !planned.api.described[k[0]] && unseen(k[0]) {
			notes = append(notes, whyAs("API", k[0], "gets a route that asks for nothing ("+k[1]+")",
				"the plan does not describe its stages or resource policy"))
		}
	}
	return dedupe(notes)
}

// openRoutes lists the routes of a state's APIs that ask for nothing, as (API, route).
func openRoutes(b apiBundle) [][2]string {
	var out [][2]string
	for _, a := range b.RestAPIs {
		for _, m := range a.Methods {
			if strings.EqualFold(m.AuthorizationType, "NONE") && !m.APIKeyRequired {
				out = append(out, [2]string{a.ID, m.HTTPMethod + " " + m.Path})
			}
		}
	}
	for _, a := range b.HTTPAPIs {
		for _, rt := range a.Routes {
			if strings.EqualFold(rt.AuthorizationType, "NONE") && !rt.APIKeyRequired {
				out = append(out, [2]string{a.APIID, rt.RouteKey})
			}
		}
	}
	return out
}

// fingerprint is a record in one comparable string.
func fingerprint(x any) string {
	b, _ := json.Marshal(x)
	return string(b)
}

func keysOfAdmits(m map[string]admits) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func keysOfPorts(m map[string]ingestion.PortSet) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
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
