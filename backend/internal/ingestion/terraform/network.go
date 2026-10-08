package terraform

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The network feed, in the shapes ec2's describe-* calls return and the cloudnet collector
// reads: security groups with their ingress, instances with their groups, subnet, profile
// and addresses, subnets with their route table, route tables with their routes, and the
// instance profiles that say which role an instance holds.

type netBundle struct {
	SecurityGroups   []sgRecord      `json:"security_groups"`
	Instances        []instRecord    `json:"instances"`
	Subnets          []subnetRecord  `json:"subnets,omitempty"`
	RouteTables      []rtRecord      `json:"route_tables,omitempty"`
	InstanceProfiles []profileRecord `json:"instance_profiles,omitempty"`
	// What a live read of the account carries and a plan does not: kept as read, so the
	// account's network passes through to cloudnet whole when the plan is laid over it.
	Provider      string          `json:"provider,omitempty"`
	VPCPeerings   json.RawMessage `json:"vpc_peerings,omitempty"`
	NetworkACLs   json.RawMessage `json:"network_acls,omitempty"`
	ECSServices   json.RawMessage `json:"ecs_services,omitempty"`
	LoadBalancers json.RawMessage `json:"load_balancers,omitempty"`

	// described are the security groups the view holds in full - those the configuration
	// manages - rather than only rules added to them; address is each instance's block in
	// the configuration.
	described map[string]bool
	address   map[string]string
}

type sgRecord struct {
	GroupID       string         `json:"GroupId"`
	GroupName     string         `json:"GroupName,omitempty"`
	IpPermissions []ipPermission `json:"IpPermissions"`
}

type ipPermission struct {
	IpProtocol       string      `json:"IpProtocol"`
	FromPort         *int        `json:"FromPort,omitempty"`
	ToPort           *int        `json:"ToPort,omitempty"`
	IpRanges         []cidrV4    `json:"IpRanges,omitempty"`
	Ipv6Ranges       []cidrV6    `json:"Ipv6Ranges,omitempty"`
	UserIdGroupPairs []groupPair `json:"UserIdGroupPairs,omitempty"`
}

type cidrV4 struct {
	CidrIp string `json:"CidrIp"`
}

type cidrV6 struct {
	CidrIpv6 string `json:"CidrIpv6"`
}

type groupPair struct {
	GroupID string `json:"GroupId"`
}

type instRecord struct {
	InstanceID         string        `json:"InstanceId"`
	SubnetID           string        `json:"SubnetId,omitempty"`
	SecurityGroups     []groupPair   `json:"SecurityGroups,omitempty"`
	Tags               []tag         `json:"Tags,omitempty"`
	IamInstanceProfile *arnRef       `json:"IamInstanceProfile,omitempty"`
	PrivateIPAddress   string        `json:"PrivateIpAddress,omitempty"`
	PublicIPAddress    string        `json:"PublicIpAddress,omitempty"`
	IPv6Address        string        `json:"Ipv6Address,omitempty"`
	MetadataOptions    *metadataOpts `json:"MetadataOptions,omitempty"`
	// NetworkInterfaces is a live instance's, kept as read.
	NetworkInterfaces json.RawMessage `json:"NetworkInterfaces,omitempty"`
}

type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type arnRef struct {
	Arn string `json:"Arn"`
}

type metadataOpts struct {
	HTTPTokens string `json:"HttpTokens"`
}

type subnetRecord struct {
	SubnetID     string `json:"SubnetId"`
	RouteTableID string `json:"RouteTableId,omitempty"`
	NetworkACLID string `json:"NetworkAclId,omitempty"`
}

type rtRecord struct {
	RouteTableID string  `json:"RouteTableId"`
	Routes       []route `json:"Routes"`
}

type route struct {
	DestinationCidrBlock     string `json:"DestinationCidrBlock,omitempty"`
	DestinationIpv6CidrBlock string `json:"DestinationIpv6CidrBlock,omitempty"`
	GatewayID                string `json:"GatewayId,omitempty"`
	NatGatewayID             string `json:"NatGatewayId,omitempty"`
	TransitGatewayID         string `json:"TransitGatewayId,omitempty"`
	VpcPeeringConnID         string `json:"VpcPeeringConnectionId,omitempty"`
	EgressOnlyIGWID          string `json:"EgressOnlyInternetGatewayId,omitempty"`
}

type profileRecord struct {
	Arn   string `json:"Arn"`
	Roles []struct {
		Arn      string `json:"Arn"`
		RoleName string `json:"RoleName"`
	} `json:"Roles"`
}

// placeholderAddress stands for an address AWS assigns on apply. Its presence says the
// instance has one; cloudnet does not read the value.
const placeholderAddress = "(assigned on apply)"

// id is a managed resource's identifier in a view: its own, or a placeholder.
func (p *Plan) id(v View, r *Resource) string {
	if s, _ := r.Values["id"].(string); s != "" {
		return s
	}
	return p.placeholder(v, r, "id")
}

// network builds the network feed of a view.
func (p *Plan) network(v View) (netBundle, []string) {
	b := netBundle{described: map[string]bool{}, address: map[string]string{}}
	var notes []string
	groups := map[string]*sgRecord{}
	var order []string
	group := func(id string) *sgRecord {
		if g, ok := groups[id]; ok {
			return g
		}
		g := &sgRecord{GroupID: id, IpPermissions: []ipPermission{}}
		groups[id] = g
		order = append(order, id)
		return g
	}

	for _, r := range p.Resources(v, "aws_security_group", "aws_default_security_group") {
		if !r.Managed() {
			continue
		}
		g := group(p.id(v, r))
		g.GroupName, _ = r.Values["name"].(string)
		b.described[g.GroupID] = true
		blocks, _ := r.Values["ingress"].([]any)
		for i := range blocks {
			perm, ok := p.ingressBlock(v, r, i)
			if !ok {
				notes = append(notes, r.Address+": an ingress rule is known only after apply")
				continue
			}
			g.IpPermissions = append(g.IpPermissions, perm)
		}
		// Without ingress blocks of its own, the attribute is computed from the rule
		// resources read below; only rules written into the group itself can be lost here.
		if cfg := p.configOf(r); unknownAt(r.Unknown, "ingress") && cfg != nil {
			if _, inline := cfg.Expressions["ingress"]; inline {
				notes = append(notes, r.Address+": its ingress rules are known only after apply")
			}
		}
	}
	for _, r := range p.Resources(v, "aws_security_group_rule") {
		if !r.Managed() || p.Str(v, r, "type") != "ingress" {
			continue
		}
		sg := p.Str(v, r, "security_group_id")
		if sg == "" {
			notes = append(notes, r.Address+": the group it opens is known only after apply")
			continue
		}
		perm := ipPermission{IpProtocol: protocol(p.Str(v, r, "protocol"))}
		perm.FromPort, perm.ToPort = ports(r.Values["from_port"], r.Values["to_port"], perm.IpProtocol)
		for _, c := range p.Strs(v, r, "cidr_blocks") {
			perm.IpRanges = append(perm.IpRanges, cidrV4{c})
		}
		for _, c := range p.Strs(v, r, "ipv6_cidr_blocks") {
			perm.Ipv6Ranges = append(perm.Ipv6Ranges, cidrV6{c})
		}
		if src := p.Str(v, r, "source_security_group_id"); src != "" {
			perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, groupPair{src})
		}
		if self, _ := r.Values["self"].(bool); self {
			perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, groupPair{sg})
		}
		if !p.Known(v, r, "cidr_blocks") || !p.Known(v, r, "ipv6_cidr_blocks") {
			notes = append(notes, r.Address+": the addresses it admits are known only after apply")
		}
		g := group(sg)
		g.IpPermissions = append(g.IpPermissions, perm)
	}
	for _, r := range p.Resources(v, "aws_vpc_security_group_ingress_rule") {
		if !r.Managed() {
			continue
		}
		sg := p.Str(v, r, "security_group_id")
		if sg == "" {
			notes = append(notes, r.Address+": the group it opens is known only after apply")
			continue
		}
		perm := ipPermission{IpProtocol: protocol(p.Str(v, r, "ip_protocol"))}
		perm.FromPort, perm.ToPort = ports(r.Values["from_port"], r.Values["to_port"], perm.IpProtocol)
		if c := p.Str(v, r, "cidr_ipv4"); c != "" {
			perm.IpRanges = append(perm.IpRanges, cidrV4{c})
		}
		if c := p.Str(v, r, "cidr_ipv6"); c != "" {
			perm.Ipv6Ranges = append(perm.Ipv6Ranges, cidrV6{c})
		}
		if src := p.Str(v, r, "referenced_security_group_id"); src != "" {
			perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, groupPair{src})
		}
		g := group(sg)
		g.IpPermissions = append(g.IpPermissions, perm)
	}
	for _, id := range order {
		b.SecurityGroups = append(b.SecurityGroups, *groups[id])
	}

	// Route tables, and which subnet uses which.
	tables := map[string]*rtRecord{}
	var rtOrder []string
	table := func(id string) *rtRecord {
		if t, ok := tables[id]; ok {
			return t
		}
		t := &rtRecord{RouteTableID: id, Routes: []route{}}
		tables[id] = t
		rtOrder = append(rtOrder, id)
		return t
	}
	for _, r := range p.Resources(v, "aws_route_table", "aws_default_route_table") {
		if !r.Managed() {
			continue
		}
		id := p.id(v, r)
		// The VPC's main table, adopted: it is the table its VPC names, whatever the
		// resource's own id says before apply.
		if r.Type == "aws_default_route_table" {
			if main := p.Str(v, r, "default_route_table_id"); main != "" {
				id = main
			}
		}
		t := table(id)
		blocks, _ := r.Values["route"].([]any)
		for i := range blocks {
			t.Routes = append(t.Routes, p.routeOf(v, r, "route", i))
		}
	}
	for _, r := range p.Resources(v, "aws_route") {
		if !r.Managed() {
			continue
		}
		rt := p.Str(v, r, "route_table_id")
		if rt == "" {
			continue
		}
		rr := route{
			DestinationCidrBlock:     p.Str(v, r, "destination_cidr_block"),
			DestinationIpv6CidrBlock: p.Str(v, r, "destination_ipv6_cidr_block"),
			GatewayID:                p.Str(v, r, "gateway_id"),
			NatGatewayID:             p.Str(v, r, "nat_gateway_id"),
			TransitGatewayID:         p.Str(v, r, "transit_gateway_id"),
			VpcPeeringConnID:         p.Str(v, r, "vpc_peering_connection_id"),
			EgressOnlyIGWID:          p.Str(v, r, "egress_only_gateway_id"),
		}
		t := table(rt)
		t.Routes = append(t.Routes, rr)
	}
	for _, id := range rtOrder {
		b.RouteTables = append(b.RouteTables, *tables[id])
	}

	subnetTable := map[string]string{}
	for _, r := range p.Resources(v, "aws_route_table_association") {
		if !r.Managed() {
			continue
		}
		if sn, rt := p.Str(v, r, "subnet_id"), p.Str(v, r, "route_table_id"); sn != "" && rt != "" {
			subnetTable[sn] = rt
		}
	}
	// A subnet with no association of its own uses its VPC's main route table. The
	// configuration names it when it manages it (aws_default_route_table, or a main
	// association); a VPC the plan creates without either gets AWS's own, which routes only
	// inside the VPC. Otherwise the main table is outside the plan, the subnet's routing
	// stays unknown, and the security groups alone decide - erring toward reporting.
	mainTable := map[string]string{} // VPC -> route table
	for _, r := range p.Resources(v, "aws_vpc") {
		if r.Managed() && contains(r.Actions, "create") && v == Planned {
			id := "rtb-" + plannedMark + r.Address + ".main"
			mainTable[p.id(v, r)] = id
			table(id)
		}
	}
	for _, r := range p.Resources(v, "aws_default_route_table") {
		if vpc := p.Str(v, r, "vpc_id"); vpc != "" && r.Managed() {
			if main := p.Str(v, r, "default_route_table_id"); main != "" {
				mainTable[vpc] = main
			}
		}
	}
	for _, r := range p.Resources(v, "aws_main_route_table_association") {
		if vpc, rt := p.Str(v, r, "vpc_id"), p.Str(v, r, "route_table_id"); vpc != "" && rt != "" && r.Managed() {
			mainTable[vpc] = rt
		}
	}
	b.RouteTables = b.RouteTables[:0]
	for _, id := range rtOrder {
		b.RouteTables = append(b.RouteTables, *tables[id])
	}

	publicOnLaunch := map[string]bool{}
	subnetKnown := map[string]bool{}
	for _, r := range p.Resources(v, "aws_subnet", "aws_default_subnet") {
		id := p.id(v, r)
		subnetKnown[id] = true
		publicOnLaunch[id], _ = r.Values["map_public_ip_on_launch"].(bool)
		if !r.Managed() {
			continue
		}
		rt := subnetTable[id]
		if rt == "" {
			rt = mainTable[p.Str(v, r, "vpc_id")]
		}
		b.Subnets = append(b.Subnets, subnetRecord{SubnetID: id, RouteTableID: rt})
	}
	// Associations of subnets the configuration does not manage still say how they route.
	for sn, rt := range subnetTable {
		if !subnetKnown[sn] {
			b.Subnets = append(b.Subnets, subnetRecord{SubnetID: sn, RouteTableID: rt})
		}
	}

	// Instance profiles, by name and ARN, and the role each carries.
	profileARN := map[string]string{}
	for _, r := range p.Resources(v, "aws_iam_instance_profile") {
		arn := p.arnOf(v, r)
		profileARN[p.nameOf(v, r)] = arn
		if !r.Managed() {
			continue
		}
		role := p.Str(v, r, "role")
		if role == "" {
			continue
		}
		rec := profileRecord{Arn: arn}
		rec.Roles = append(rec.Roles, struct {
			Arn      string `json:"Arn"`
			RoleName string `json:"RoleName"`
		}{Arn: p.roleARN(v, role), RoleName: role})
		b.InstanceProfiles = append(b.InstanceProfiles, rec)
	}

	// Elastic IPs give an instance a public address whatever its subnet does.
	eip := map[string]bool{}
	for _, r := range p.Resources(v, "aws_eip") {
		if inst := p.Str(v, r, "instance"); inst != "" {
			eip[inst] = true
		}
	}
	for _, r := range p.Resources(v, "aws_eip_association") {
		if inst := p.Str(v, r, "instance_id"); inst != "" {
			eip[inst] = true
		}
	}
	// Groups named, as an instance outside a VPC names them, by name.
	groupByName := map[string]string{}
	for _, r := range p.Resources(v, "aws_security_group") {
		if name, _ := r.Values["name"].(string); name != "" {
			groupByName[name] = p.id(v, r)
		}
	}

	for _, r := range p.Resources(v, "aws_instance") {
		if !r.Managed() {
			continue
		}
		id := p.id(v, r)
		b.address[id] = r.Address
		rec := instRecord{InstanceID: id, SubnetID: p.Str(v, r, "subnet_id")}
		groupIDs := p.Strs(v, r, "vpc_security_group_ids")
		if len(groupIDs) == 0 {
			for _, name := range p.Strs(v, r, "security_groups") {
				if id := groupByName[name]; id != "" {
					groupIDs = append(groupIDs, id)
				} else if strings.HasPrefix(name, "sg-") {
					groupIDs = append(groupIDs, name)
				}
			}
		}
		for _, sg := range groupIDs {
			rec.SecurityGroups = append(rec.SecurityGroups, groupPair{sg})
		}
		if tags, ok := r.Values["tags"].(map[string]any); ok {
			rec.Tags = tagList(tags)
		}
		if prof := p.Str(v, r, "iam_instance_profile"); prof != "" {
			arn := profileARN[prof]
			if arn == "" {
				arn = "arn:aws:iam::" + p.accountOr() + ":instance-profile/" + prof
			}
			rec.IamInstanceProfile = &arnRef{arn}
		}
		if tokens, ok := dig(r.Values, "metadata_options", 0, "http_tokens"); ok {
			if s, _ := tokens.(string); s != "" {
				rec.MetadataOptions = &metadataOpts{HTTPTokens: s}
			}
		}
		// Addresses: what the instance has, when AWS already gave it; otherwise what it
		// will get - a public address when it asks for one, when an Elastic IP is bound
		// to it, or when its subnet hands them out. When none of that can be told, no
		// address is recorded and the security groups alone decide.
		pub, pubKnown := r.Values["public_ip"].(string)
		pubKnown = pubKnown && !unknownAt(r.Unknown, "public_ip")
		assoc, assocKnown := r.Values["associate_public_ip_address"].(bool)
		addressed := true
		switch {
		case eip[id] || (assocKnown && assoc):
			pub = placeholderAddress
		case pubKnown:
			// AWS already said: an address, or none.
		case assocKnown && !assoc:
			pub = ""
		case subnetKnown[rec.SubnetID] && publicOnLaunch[rec.SubnetID]:
			pub = placeholderAddress
		case subnetKnown[rec.SubnetID]:
			pub = "" // its subnet hands out none
		default:
			addressed = false
		}
		if addressed {
			rec.PublicIPAddress = pub
			rec.PrivateIPAddress, _ = r.Values["private_ip"].(string)
			if rec.PrivateIPAddress == "" {
				rec.PrivateIPAddress = placeholderAddress
			}
		}
		if n, _ := r.Values["ipv6_address_count"].(float64); n > 0 {
			rec.IPv6Address = placeholderAddress
		}
		if l, _ := r.Values["ipv6_addresses"].([]any); len(l) > 0 {
			rec.IPv6Address = fmt.Sprint(l[0])
		}
		b.Instances = append(b.Instances, rec)
	}
	return b, notes
}

func (p *Plan) accountOr() string {
	if p.Account != "" {
		return p.Account
	}
	return "planned"
}

// roleARN turns what names a role - its name, as an instance profile or an attachment
// writes it, or its ARN - into its ARN: the configuration's own role when it manages one
// of that name, otherwise the ARN AWS would give a role of that name at the root path.
func (p *Plan) roleARN(v View, nameOrARN string) string {
	if strings.HasPrefix(nameOrARN, "arn:") {
		return nameOrARN
	}
	// Indexed once per view: every profile and attachment names a role, and looking each
	// up among all the roles would cost the square of the plan.
	byName, ok := p.roles[v]
	if !ok {
		byName = map[string]string{}
		for _, r := range p.Resources(v, "aws_iam_role") {
			if name := p.nameOf(v, r); byName[name] == "" {
				byName[name] = p.arnOf(v, r)
			}
		}
		p.roles[v] = byName
	}
	if arn := byName[nameOrARN]; arn != "" {
		return arn
	}
	return "arn:aws:iam::" + p.accountOr() + ":role/" + nameOrARN
}

// ingressBlock reads an inline ingress block of a security group.
func (p *Plan) ingressBlock(v View, r *Resource, i int) (ipPermission, bool) {
	blk, ok := dig(r.Values, "ingress", i)
	m, isMap := blk.(map[string]any)
	if !ok || !isMap {
		return ipPermission{}, false
	}
	proto, _ := m["protocol"].(string)
	perm := ipPermission{IpProtocol: protocol(proto)}
	perm.FromPort, perm.ToPort = ports(m["from_port"], m["to_port"], perm.IpProtocol)
	for _, c := range strList(m["cidr_blocks"]) {
		perm.IpRanges = append(perm.IpRanges, cidrV4{c})
	}
	for _, c := range strList(m["ipv6_cidr_blocks"]) {
		perm.Ipv6Ranges = append(perm.Ipv6Ranges, cidrV6{c})
	}
	for _, sg := range p.Strs(v, r, "ingress", i, "security_groups") {
		perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, groupPair{sg})
	}
	if self, _ := m["self"].(bool); self {
		perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, groupPair{p.id(v, r)})
	}
	return perm, true
}

func (p *Plan) routeOf(v View, r *Resource, block string, i int) route {
	s := func(attr string) string {
		x, _ := p.Attr(v, r, block, i, attr)
		str, _ := x.(string)
		return str
	}
	return route{
		DestinationCidrBlock:     s("cidr_block"),
		DestinationIpv6CidrBlock: s("ipv6_cidr_block"),
		GatewayID:                s("gateway_id"),
		NatGatewayID:             s("nat_gateway_id"),
		TransitGatewayID:         s("transit_gateway_id"),
		VpcPeeringConnID:         s("vpc_peering_connection_id"),
		EgressOnlyIGWID:          s("egress_only_gateway_id"),
	}
}

// protocol turns Terraform's spelling of a protocol into EC2's: "-1" and "all" are every
// protocol, the rest pass as they are.
func protocol(p string) string {
	switch strings.ToLower(p) {
	case "", "-1", "all":
		return "-1"
	}
	return strings.ToLower(p)
}

// ports reads a rule's port range; every protocol has no range.
func ports(from, to any, proto string) (*int, *int) {
	if proto == "-1" {
		return nil, nil
	}
	f, fok := toInt(from)
	t, tok := toInt(to)
	if !fok || !tok {
		return nil, nil
	}
	return &f, &t
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(t)
		return n, err == nil
	}
	return 0, false
}

func strList(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, e := range l {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func tagList(m map[string]any) []tag {
	var out []tag
	for k, v := range m {
		s, _ := v.(string)
		out = append(out, tag{Key: k, Value: s})
	}
	sortTags(out)
	return out
}

func sortTags(t []tag) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].Key < t[j-1].Key; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}

// unchangedExposure lists the instances present in both states whose exposure the plan
// leaves as it was: the same subnet with the same routes, the same groups with the same
// rules, the same addresses.
func unchangedExposure(prior, planned netBundle) []string {
	was := map[string]string{}
	before := indexNet(prior)
	for _, inst := range prior.Instances {
		was[inst.InstanceID] = before.exposureInputs(inst)
	}
	after := indexNet(planned)
	var out []string
	for _, inst := range planned.Instances {
		if fp, ok := was[inst.InstanceID]; ok && fp == after.exposureInputs(inst) {
			out = append(out, inst.InstanceID)
		}
	}
	return out
}

// netIndex is a view's network keyed for lookup: built once, so that comparing every
// instance stays linear in the size of the plan - which its author writes - and not in its
// square.
type netIndex struct {
	groups  map[string]sgRecord
	tableOf map[string]string  // subnet -> route table
	routes  map[string][]route // route table -> routes
}

func indexNet(b netBundle) netIndex {
	ix := netIndex{groups: map[string]sgRecord{}, tableOf: map[string]string{}, routes: map[string][]route{}}
	for _, g := range b.SecurityGroups {
		ix.groups[g.GroupID] = g
	}
	for _, sn := range b.Subnets {
		ix.tableOf[sn.SubnetID] = sn.RouteTableID
	}
	for _, t := range b.RouteTables {
		ix.routes[t.RouteTableID] = t.Routes
	}
	return ix
}

// exposureInputs is everything the network feed decides an instance's exposure from, in
// one comparable string.
func (ix netIndex) exposureInputs(inst instRecord) string {
	var routes []route
	if rt, ok := ix.tableOf[inst.SubnetID]; ok {
		routes = ix.routes[rt]
	}
	var ids []string
	for _, g := range inst.SecurityGroups {
		ids = append(ids, g.GroupID)
	}
	sort.Strings(ids)
	var perms []sgRecord
	for _, id := range ids {
		perms = append(perms, ix.groups[id])
	}
	fp, _ := json.Marshal(map[string]any{
		"subnet": inst.SubnetID, "groups": perms, "routes": routes,
		"public": inst.PublicIPAddress != "", "private": inst.PrivateIPAddress != "", "v6": inst.IPv6Address != "",
	})
	return string(fp)
}
