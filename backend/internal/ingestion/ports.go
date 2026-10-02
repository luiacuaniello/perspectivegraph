package ingestion

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The transports exposure analysis tells apart. ICMP and ICMPv6 have no ports: a set
// holds them as the single range 0-0.
const (
	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoICMP   = "icmp"
	ProtoICMPv6 = "icmpv6"
)

const maxPort = 65535

// portRange is an inclusive range of ports.
type portRange struct{ from, to int }

// PortSet is which ports of which transports are open: transport -> sorted, merged
// ranges. The zero value is the empty set. Firewalls - security groups, network ACLs,
// network security groups - speak in protocols and port ranges, and an instance is only
// as exposed as the ports every one of them lets through.
type PortSet map[string][]portRange

// AllPorts is every port of every transport: a rule for "all traffic".
func AllPorts() PortSet {
	return PortSet{
		ProtoTCP: {{0, maxPort}}, ProtoUDP: {{0, maxPort}},
		ProtoICMP: {{0, 0}}, ProtoICMPv6: {{0, 0}},
	}
}

// RulePorts is the set a firewall rule covers, from its protocol and port range as AWS
// and Azure write them. A missing protocol means all traffic, which is what an export
// that predates ports meant; a missing or negative bound means the whole range. A
// protocol other than TCP, UDP or ICMP (ESP, GRE…) carries no service to attack and is
// left out.
func RulePorts(protocol string, from, to *int) PortSet {
	lo, hi := 0, maxPort
	if from != nil && *from >= 0 {
		lo = *from
	}
	if to != nil && *to >= 0 {
		hi = *to
	}
	return protoPorts(protocol, lo, hi)
}

// RulePortSpecs is RulePorts for Azure's port syntax: "*", "22", "80-443", or a list.
func RulePortSpecs(protocol string, specs []string) PortSet {
	out := PortSet{}
	if len(specs) == 0 {
		specs = []string{"*"}
	}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		lo, hi := 0, maxPort
		if spec != "*" && spec != "" {
			a, b, isRange := strings.Cut(spec, "-")
			x, err := strconv.Atoi(strings.TrimSpace(a))
			if err != nil {
				continue
			}
			lo, hi = x, x
			if isRange {
				if y, err := strconv.Atoi(strings.TrimSpace(b)); err == nil {
					hi = y
				}
			}
		}
		out = out.Union(protoPorts(protocol, lo, hi))
	}
	return out
}

func protoPorts(protocol string, lo, hi int) PortSet {
	if lo > hi {
		lo, hi = hi, lo
	}
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "-1", "all", "*", "any":
		return AllPorts()
	case "tcp", "6":
		return PortSet{ProtoTCP: {{lo, hi}}}
	case "udp", "17":
		return PortSet{ProtoUDP: {{lo, hi}}}
	case "icmp", "1":
		return PortSet{ProtoICMP: {{0, 0}}}
	case "icmpv6", "58":
		return PortSet{ProtoICMPv6: {{0, 0}}}
	}
	return PortSet{}
}

// Union is every port in either set.
func (s PortSet) Union(o PortSet) PortSet {
	out := PortSet{}
	for _, set := range []PortSet{s, o} {
		for p, rs := range set {
			out[p] = merge(append(append([]portRange(nil), out[p]...), rs...))
		}
	}
	return out
}

// Intersect is every port in both sets.
func (s PortSet) Intersect(o PortSet) PortSet {
	out := PortSet{}
	for p, a := range s {
		var rs []portRange
		for _, x := range a {
			for _, y := range o[p] {
				if lo, hi := max(x.from, y.from), min(x.to, y.to); lo <= hi {
					rs = append(rs, portRange{lo, hi})
				}
			}
		}
		if len(rs) > 0 {
			out[p] = merge(rs)
		}
	}
	return out
}

// Minus is every port in s and not in o.
func (s PortSet) Minus(o PortSet) PortSet {
	out := PortSet{}
	for p, a := range s {
		rs := append([]portRange(nil), a...)
		for _, y := range o[p] {
			var next []portRange
			for _, x := range rs {
				if y.to < x.from || y.from > x.to {
					next = append(next, x)
					continue
				}
				if x.from < y.from {
					next = append(next, portRange{x.from, y.from - 1})
				}
				if x.to > y.to {
					next = append(next, portRange{y.to + 1, x.to})
				}
			}
			rs = next
		}
		if len(rs) > 0 {
			out[p] = rs
		}
	}
	return out
}

// PortRule is one transport and port range of a set, for writing it back out as rules.
type PortRule struct {
	Proto    string
	From, To int
}

// Rules lists the set as one rule per transport and range, transports in a fixed order.
func (s PortSet) Rules() []PortRule {
	var out []PortRule
	for _, p := range []string{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6} {
		for _, r := range s[p] {
			out = append(out, PortRule{Proto: p, From: r.from, To: r.to})
		}
	}
	return out
}

// Empty reports whether no port is open.
func (s PortSet) Empty() bool {
	for _, rs := range s {
		if len(rs) > 0 {
			return false
		}
	}
	return true
}

// Transport reports whether a TCP or UDP port is open - a service an attacker can talk
// to. ICMP alone answers a ping and offers nothing to exploit.
func (s PortSet) Transport() bool {
	return len(s[ProtoTCP]) > 0 || len(s[ProtoUDP]) > 0
}

// String renders the set the way people read firewall rules: "tcp/22, tcp/8000-8080,
// udp/all, icmp", transports in a fixed order.
func (s PortSet) String() string {
	var parts []string
	for _, p := range []string{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6} {
		for _, r := range s[p] {
			switch {
			case p == ProtoICMP || p == ProtoICMPv6:
				parts = append(parts, p)
			case r.from == 0 && r.to == maxPort:
				parts = append(parts, p+"/all")
			case r.from == r.to:
				parts = append(parts, fmt.Sprintf("%s/%d", p, r.from))
			default:
				parts = append(parts, fmt.Sprintf("%s/%d-%d", p, r.from, r.to))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// managementPorts are the services that hand over a machine or its data when they answer
// the internet: remote shells and desktops, container and cluster control planes, and
// databases and caches that are not meant to face it.
var managementPorts = PortSet{ProtoTCP: merge([]portRange{
	{22, 22}, {23, 23}, {3389, 3389}, {5985, 5986}, {5900, 5900}, // SSH, Telnet, RDP, WinRM, VNC
	{2375, 2376}, {6443, 6443}, {10250, 10250}, {2379, 2380}, // Docker, Kubernetes API, kubelet, etcd
	{3306, 3306}, {5432, 5432}, {1433, 1433}, {1521, 1521}, // MySQL, PostgreSQL, SQL Server, Oracle
	{6379, 6379}, {27017, 27017}, {9200, 9200}, {11211, 11211}, // Redis, MongoDB, Elasticsearch, Memcached
})}

// Management is the part of the set that reaches a management or data service.
func (s PortSet) Management() PortSet { return s.Intersect(managementPorts) }

// FirewallRule is one rule of a first-match firewall - a network ACL, a network
// security group - as it applies to traffic from the internet.
type FirewallRule struct {
	Ports PortSet
	Allow bool
}

// FirstMatch is what a first-match firewall lets through of the ports offered to it:
// rules apply in order, each deciding the ports no earlier rule decided, and what no
// rule decides is denied.
func FirstMatch(offered PortSet, rules []FirewallRule) PortSet {
	undecided, allowed := offered, PortSet{}
	for _, r := range rules {
		hit := undecided.Intersect(r.Ports)
		if hit.Empty() {
			continue
		}
		if r.Allow {
			allowed = allowed.Union(hit)
		}
		undecided = undecided.Minus(hit)
	}
	return allowed
}

// merge sorts ranges and joins the ones that overlap or touch.
func merge(rs []portRange) []portRange {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].from < rs[j].from })
	out := []portRange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.from <= last.to+1 {
			last.to = max(last.to, r.to)
			continue
		}
		out = append(out, r)
	}
	return out
}
