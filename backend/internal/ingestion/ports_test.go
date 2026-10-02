package ingestion

import "testing"

func ptr(i int) *int { return &i }

// Rules read the way AWS and Azure write them, and render the way people read them.
func TestPortSetReadsAndRendersRules(t *testing.T) {
	for _, c := range []struct {
		name string
		set  PortSet
		want string
	}{
		{"AWS tcp 22", RulePorts("tcp", ptr(22), ptr(22)), "tcp/22"},
		{"AWS all traffic", RulePorts("-1", nil, nil), "tcp/all, udp/all, icmp, icmpv6"},
		{"AWS numeric udp range", RulePorts("17", ptr(1000), ptr(2000)), "udp/1000-2000"},
		{"AWS icmp, type/code in the port fields", RulePorts("icmp", ptr(8), ptr(-1)), "icmp"},
		{"no protocol means all, as before ports were read", RulePorts("", nil, nil), "tcp/all, udp/all, icmp, icmpv6"},
		{"ESP carries no service", RulePorts("50", nil, nil), ""},
		{"Azure single and range", RulePortSpecs("Tcp", []string{"22", "8000-8080"}), "tcp/22, tcp/8000-8080"},
		{"Azure star", RulePortSpecs("*", []string{"*"}), "tcp/all, udp/all, icmp, icmpv6"},
		{"adjacent ranges join", RulePorts("tcp", ptr(80), ptr(80)).Union(RulePorts("tcp", ptr(81), ptr(90))), "tcp/80-90"},
	} {
		if got := c.set.String(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPortSetArithmetic(t *testing.T) {
	all := RulePorts("tcp", nil, nil)
	web := RulePorts("tcp", ptr(443), ptr(443))
	if got := all.Minus(web).String(); got != "tcp/0-442, tcp/444-65535" {
		t.Errorf("all minus 443 = %q", got)
	}
	if got := all.Intersect(web).String(); got != "tcp/443" {
		t.Errorf("all ∩ 443 = %q", got)
	}
	if icmp := RulePorts("icmp", nil, nil); icmp.Empty() || icmp.Transport() {
		t.Error("ICMP alone is not a transport an attacker can talk to")
	}
	if got := RulePorts("tcp", ptr(20), ptr(25)).Management().String(); got != "tcp/22-23" {
		t.Errorf("management ports in 20-25 = %q, want SSH and Telnet", got)
	}
}

// A network ACL is first-match: an allow on 443 followed by a deny on everything lets
// 443 through and nothing else - so a security group open on 22 is not exposed on 22.
func TestFirstMatch(t *testing.T) {
	offered := RulePorts("tcp", ptr(22), ptr(22)).Union(RulePorts("tcp", ptr(443), ptr(443)))
	allowed := FirstMatch(offered, []FirewallRule{
		{Ports: RulePorts("tcp", ptr(443), ptr(443)), Allow: true},
		{Ports: AllPorts(), Allow: false},
	})
	if got := allowed.String(); got != "tcp/443" {
		t.Errorf("allowed %q, want only tcp/443", got)
	}
	// An earlier deny wins over a later allow.
	allowed = FirstMatch(offered, []FirewallRule{
		{Ports: RulePorts("tcp", ptr(22), ptr(22)), Allow: false},
		{Ports: AllPorts(), Allow: true},
	})
	if got := allowed.String(); got != "tcp/443" {
		t.Errorf("allowed %q, want tcp/443 - the deny on 22 came first", got)
	}
	// What no rule decides is denied.
	if got := FirstMatch(offered, nil); !got.Empty() {
		t.Errorf("no rules let through %q", got)
	}
}
