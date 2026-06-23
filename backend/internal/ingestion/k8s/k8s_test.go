package k8s

import (
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A non-admin Role that grants an escalation primitive (here: read all secrets)
// must draw a CAN_ESCALATE_TO edge to the synthetic cluster-admin crown jewel -
// the deep-RBAC modeling the shallow name/wildcard check misses.
func TestRBACEscalationPrimitive(t *testing.T) {
	in := `[
	  {"kind":"ServiceAccount","metadata":{"name":"reader","namespace":"prod"}},
	  {"kind":"ClusterRole","metadata":{"name":"secret-reader"},
	   "rules":[{"verbs":["get","list"],"resources":["secrets"],"apiGroups":[""]}]},
	  {"kind":"ClusterRoleBinding","metadata":{"name":"b"},
	   "roleRef":{"kind":"ClusterRole","name":"secret-reader"},
	   "subjects":[{"kind":"ServiceAccount","name":"reader","namespace":"prod"}]}
	]`
	events, err := New().Parse(strings.NewReader(in), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := events[0]

	caID := ontology.NewID(ontology.LabelIAMRole, "perspectivegraph:cluster-admin")
	roleID := ontology.NewID(ontology.LabelIAMRole, "secret-reader")
	var ca *ontology.Node
	for i := range ev.Nodes {
		if ev.Nodes[i].ID == caID {
			ca = &ev.Nodes[i]
		}
	}
	if ca == nil || !ca.Bool(ontology.PropCrownJewel) {
		t.Fatal("expected a synthetic cluster-admin crown jewel")
	}
	var escalates bool
	for _, e := range ev.Edges {
		if e.Type == ontology.EdgeCanEscalateTo && e.From == roleID && e.To == caID {
			escalates = true
		}
	}
	if !escalates {
		t.Errorf("secret-reading role should CAN_ESCALATE_TO cluster-admin; edges=%v", ev.Edges)
	}
}

func TestEscalateReasonClassification(t *testing.T) {
	rule := func(verbs, resources []string) item {
		it := item{}
		it.Rules = append(it.Rules, struct {
			Verbs     []string `json:"verbs"`
			Resources []string `json:"resources"`
			APIGroups []string `json:"apiGroups"`
		}{Verbs: verbs, Resources: resources})
		return it
	}
	cases := []struct {
		name       string
		verbs, res []string
		want       string
	}{
		{"create pods", []string{"create"}, []string{"pods"}, "workloads/create"},
		{"bind roles", []string{"bind"}, []string{"clusterroles"}, "rolebindings/bind"},
		{"impersonate", []string{"impersonate"}, []string{"users"}, "impersonate"},
		{"benign get pods", []string{"get"}, []string{"pods"}, ""},
	}
	for _, c := range cases {
		if got := escalateReason(rule(c.verbs, c.res)); got != c.want {
			t.Errorf("%s: escalateReason = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestContainerEscape(t *testing.T) {
	in := `[
	  {"kind":"Pod","metadata":{"name":"node-agent","namespace":"kube-system"},
	   "spec":{"containers":[{"name":"agent","image":"agent:1","securityContext":{"privileged":true}}]}},
	  {"kind":"Pod","metadata":{"name":"hostpath-pod","namespace":"prod"},
	   "spec":{"volumes":[{"hostPath":{"path":"/"}}],"containers":[{"name":"c","image":"c:1"}]}},
	  {"kind":"Pod","metadata":{"name":"safe","namespace":"prod"},
	   "spec":{"containers":[{"name":"c","image":"c:1"}]}}
	]`
	events, err := New().Parse(strings.NewReader(in), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := events[0]

	caID := ontology.NewID(ontology.LabelIAMRole, "perspectivegraph:cluster-admin")
	priv := ontology.NewID(ontology.LabelContainer, "kube-system/node-agent")
	hostPath := ontology.NewID(ontology.LabelContainer, "prod/hostpath-pod")
	safe := ontology.NewID(ontology.LabelContainer, "prod/safe")

	byID := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byID[n.ID] = n
	}
	escapes := func(from string) bool {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeEscapesTo && e.From == from && e.To == caID {
				return true
			}
		}
		return false
	}

	if !escapes(priv) {
		t.Error("a privileged pod should ESCAPES_TO cluster-admin")
	}
	if byID[priv].Properties["k8s_escape"] != "privileged container" {
		t.Errorf("privileged escape reason = %v, want 'privileged container'", byID[priv].Properties["k8s_escape"])
	}
	if !escapes(hostPath) {
		t.Error("a hostPath-mounting pod should ESCAPES_TO cluster-admin")
	}
	if escapes(safe) {
		t.Error("a pod respecting its container boundary must NOT have an escape edge")
	}
}

func TestDiscoversExposureTopology(t *testing.T) {
	f, err := os.Open("../../../testdata/k8s-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	events, err := New().Parse(f, ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ev := events[0]

	byID := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byID[n.ID] = n
	}
	has := func(t ontology.EdgeType, from, to string) bool {
		for _, e := range ev.Edges {
			if e.Type == t && e.From == from && e.To == to {
				return true
			}
		}
		return false
	}

	ingressID := ontology.NewID(ontology.LabelLoadBalancer, "ing/prod/payments-ingress")
	svcID := ontology.NewID(ontology.LabelLoadBalancer, "svc/prod/payments-svc")
	podID := ontology.NewID(ontology.LabelContainer, "prod/payments-7d9f")
	saID := ontology.NewID(ontology.LabelServiceAccount, "prod/payments-sa")
	roleID := ontology.NewID(ontology.LabelIAMRole, "cluster-admin")

	// Internet entry point.
	if ing, ok := byID[ingressID]; !ok || !ing.Bool(ontology.PropInternetExposed) {
		t.Errorf("ingress should be an internet-exposed LoadBalancer: %+v", ing)
	}
	// The full discovered chain.
	if !has(ontology.EdgeRoutesTo, ingressID, svcID) {
		t.Error("missing Ingress --ROUTES_TO--> Service")
	}
	if !has(ontology.EdgeExposes, svcID, podID) {
		t.Error("missing Service --EXPOSES--> Pod (selector match)")
	}
	if !has(ontology.EdgeAssumes, podID, saID) {
		t.Error("missing Pod --ASSUMES--> ServiceAccount")
	}
	if !has(ontology.EdgeAssumes, saID, roleID) {
		t.Error("missing ServiceAccount --ASSUMES--> Role (binding)")
	}
	// cluster-admin is a crown jewel.
	if role, ok := byID[roleID]; !ok || !role.Bool(ontology.PropCrownJewel) {
		t.Errorf("cluster-admin role should be a crown jewel: %+v", role)
	}
	// The pod carries an image ref so the normalizer stitches it to the scanned image.
	if pod := byID[podID]; pod.Properties[ontology.PropImageRef] != "registry.example.com/payments-api:1.4.2" {
		t.Errorf("pod missing image_ref for image stitching: %+v", pod.Properties)
	}
}

func TestEmptySelectorMatchesNothing(t *testing.T) {
	if selectorMatches(nil, map[string]string{"app": "x"}) {
		t.Error("empty selector must not match (matches everything would be wrong)")
	}
	if !selectorMatches(map[string]string{"app": "x"}, map[string]string{"app": "x", "tier": "web"}) {
		t.Error("selector must match a labels superset")
	}
}
