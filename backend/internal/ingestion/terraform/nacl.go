package terraform

import (
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
)

// Network ACLs, in describe-network-acls' shape: per ACL its entries, and which ACL each
// subnet uses. An ACL is first-match by rule number and stateless; cloudnet reads the
// entries on the whole internet to decide which ports reach a subnet. A subnet with no
// association of its own uses its VPC's default ACL, which lets everything in unless
// someone changed it: only the associations the plan names are read, and a subnet without
// one is judged as if its ACL let everything in - erring toward reporting.

// networkACLs reads the view's ACLs into b, and which subnet uses which.
func (p *Plan) networkACLs(v View, b *netBundle) []string {
	var notes []string
	acls := map[string]*entryList{}
	var order []string
	acl := func(id string) *entryList {
		if a, ok := acls[id]; ok {
			return a
		}
		a := &entryList{}
		acls[id] = a
		order = append(order, id)
		return a
	}
	assoc := map[string]string{} // subnet -> ACL
	// An ACL whose entries are rule resources, not written into it, shows them as AWS has
	// them when the plan is made: a rule the plan deletes is still there. Those go here.
	var dropped map[string][]entryKey
	if v == Planned {
		dropped = p.droppedACLEntries()
	}

	for _, r := range p.Resources(v, "aws_network_acl", "aws_default_network_acl") {
		if !r.Managed() {
			continue
		}
		id := p.id(v, r)
		if r.Type == "aws_default_network_acl" {
			if d := p.Str(v, r, "default_network_acl_id"); d != "" {
				id = d
			}
		}
		a := acl(id)
		b.described[id] = true
		cfg := p.configOf(r)
		for _, dir := range []string{"ingress", "egress"} {
			inline := false
			if cfg != nil {
				_, inline = cfg.Expressions[dir]
			}
			blocks, _ := r.Values[dir].([]any)
			for _, blk := range blocks {
				m, ok := blk.(map[string]any)
				if !ok {
					continue
				}
				e := naclEntryOf(m, dir == "egress", "rule_no", "action")
				if !inline && hasKey(dropped[id], entryKey{e.Egress, e.RuleNumber}) {
					continue
				}
				a.set(e)
			}
		}
		// Entries written into the ACL itself, known only after apply, are entries lost;
		// without them the attribute is computed from the rule resources read below.
		notes = append(notes, p.unknownBlocks(v, r, "ingress", "its ingress entries", "rule_no", "action", "protocol",
			"from_port", "to_port", "cidr_block", "ipv6_cidr_block")...)
		for _, sn := range p.Strs(v, r, "subnet_ids") {
			assoc[sn] = id
		}
	}
	for _, r := range p.Resources(v, "aws_network_acl_rule") {
		if !r.Managed() {
			continue
		}
		id := p.Str(v, r, "network_acl_id")
		if id == "" {
			notes = append(notes, r.Address+": the network ACL it changes is known only after apply")
			continue
		}
		egress, _ := r.Values["egress"].(bool)
		a := acl(id)
		a.set(naclEntryOf(r.Values, egress, "rule_number", "rule_action"))
	}
	for _, r := range p.Resources(v, "aws_network_acl_association") {
		if !r.Managed() {
			continue
		}
		if sn, id := p.Str(v, r, "subnet_id"), p.Str(v, r, "network_acl_id"); sn != "" && id != "" {
			assoc[sn] = id
		}
	}

	at := map[string]int{}
	for i, sn := range b.Subnets {
		at[sn.SubnetID] = i
	}
	for _, sn := range sortedKeys(keysOf(assoc)) {
		if i, ok := at[sn]; ok {
			b.Subnets[i].NetworkACLID = assoc[sn]
			continue
		}
		b.Subnets = append(b.Subnets, subnetRecord{SubnetID: sn, NetworkACLID: assoc[sn]})
	}
	for _, id := range order {
		b.NetworkACLs = append(b.NetworkACLs, naclRecord{NetworkACLID: id, Entries: acls[id].list()})
	}
	return notes
}

// naclEntryOf reads one entry, written inline in an ACL (rule_no, action) or as a rule
// resource (rule_number, rule_action), into EC2's shape.
func naclEntryOf(m map[string]any, egress bool, numberKey, actionKey string) naclEntry {
	str := func(k string) string {
		s, _ := m[k].(string)
		return s
	}
	n, _ := toInt(m[numberKey])
	e := naclEntry{RuleNumber: n, Egress: egress, CidrBlock: str("cidr_block"), Ipv6CidrBlock: str("ipv6_cidr_block"),
		RuleAction: strings.ToLower(str(actionKey)), Protocol: protocol(str("protocol"))}
	if e.Protocol != "-1" {
		from, fok := toInt(m["from_port"])
		to, tok := toInt(m["to_port"])
		if fok && tok {
			e.PortRange = &portBounds{From: &from, To: &to}
		}
	}
	return e
}

// entryList is an ACL's entries, one per rule number and direction, as AWS keeps them: an
// entry set again replaces the one of its number.
type entryList struct {
	entries []naclEntry
	at      map[entryKey]int
}

func newEntryList(entries []naclEntry) *entryList {
	l := &entryList{}
	for _, e := range entries {
		l.set(e)
	}
	return l
}

func (l *entryList) set(e naclEntry) {
	if l.at == nil {
		l.at = map[entryKey]int{}
	}
	k := entryKey{e.Egress, e.RuleNumber}
	if i, ok := l.at[k]; ok {
		l.entries[i] = e
		return
	}
	l.at[k] = len(l.entries)
	l.entries = append(l.entries, e)
}

func (l *entryList) list() []naclEntry {
	if l.entries == nil {
		return []naclEntry{}
	}
	return l.entries
}

// aclAdmits is what an ACL lets in from the whole internet, per address family: what its
// first-match entries on 0.0.0.0/0 and ::/0 allow of every port.
func aclAdmits(a naclRecord) (v4, v6 ingestion.PortSet) {
	es := append([]naclEntry(nil), a.Entries...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].RuleNumber < es[j].RuleNumber })
	var r4, r6 []ingestion.FirewallRule
	for _, e := range es {
		if e.Egress {
			continue
		}
		var from, to *int
		if e.PortRange != nil {
			from, to = e.PortRange.From, e.PortRange.To
		}
		rule := ingestion.FirewallRule{Ports: ingestion.RulePorts(e.Protocol, from, to), Allow: e.RuleAction == "allow"}
		if e.CidrBlock == "0.0.0.0/0" {
			r4 = append(r4, rule)
		}
		if e.Ipv6CidrBlock == "::/0" {
			r6 = append(r6, rule)
		}
	}
	return ingestion.FirstMatch(ingestion.AllPorts(), r4), ingestion.FirstMatch(ingestion.AllPorts(), r6)
}

func hasKey(keys []entryKey, k entryKey) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

func keysOf(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
