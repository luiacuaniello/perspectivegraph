package ingestion_test

// The same thing reported by two sources must be one node, and two things that merely
// share a name must stay two. Each case below was a wrong route, found by running the
// sources together: a role and an instance seen by Custodian and by the AWS feeds, an AWS
// role and a Kubernetes ClusterRole of the same name, two clusters, two namespaces.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/dataclass"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/eks"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/falco"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/lambda"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/supplychain"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/trivy"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func applyBody(t *testing.T, ctx context.Context, store graph.Store, c ingestion.Collector, body string, opts ingestion.Options) {
	t.Helper()
	events, err := c.Parse(strings.NewReader(body), opts)
	if err != nil {
		t.Fatalf("%s parse: %v", c.Source(), err)
	}
	n := normalizerFor(t, ctx, store)
	for _, ev := range events {
		if err := n.Handle(ctx, ev); err != nil {
			t.Fatalf("apply %s: %v", c.Source(), err)
		}
	}
}

// routeNames renders each route as "a -> b -> c", for messages and lookups.
func routeNames(paths []analyzer.AttackPath) []string {
	var out []string
	for _, p := range paths {
		var names []string
		for _, n := range p.Nodes {
			names = append(names, n.Name)
		}
		out = append(out, strings.Join(names, " -> "))
	}
	return out
}

func nodesNamed(t *testing.T, ctx context.Context, store graph.Store, label ontology.Label, name string) int {
	t.Helper()
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, node := range snap.Nodes {
		if node.Label == label && node.Name == name {
			n++
		}
	}
	return n
}

// Custodian keyed roles on their name and the iam collector on their ARN, so one role was
// two nodes, and the escalation iam found was out of reach of the instance Custodian found.
func TestCustodianAndIAMDescribeOneRole(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, custodian.New(), `{"account_id":"123456789012","policies":[
	 {"resource":"aws.ec2","resources":[{"InstanceId":"i-2","PublicIpAddress":"203.0.113.10",
	   "IamInstanceProfile":{"Arn":"arn:aws:iam::123456789012:instance-profile/app"},"Tags":[{"Key":"Name","Value":"app-vm"}]}]},
	 {"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"app","Arn":"arn:aws:iam::123456789012:instance-profile/app",
	   "Roles":[{"RoleName":"app","Arn":"arn:aws:iam::123456789012:role/app"}]}]},
	 {"resource":"aws.iam-role","resources":[{"RoleName":"app","Arn":"arn:aws:iam::123456789012:role/app"}]}]}`, ingestion.Options{})
	applyBody(t, ctx, store, iam.New(), `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[
	 {"RoleName":"app","Arn":"arn:aws:iam::123456789012:role/app","AssumeRolePolicyDocument":{"Statement":[]},
	  "RolePolicyList":[{"PolicyName":"esc","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":["iam:AttachRolePolicy"],"Resource":"*"}]}}],
	  "AttachedManagedPolicies":[]}]}`, ingestion.Options{})

	if n := nodesNamed(t, ctx, store, ontology.LabelIAMRole, "app"); n != 1 {
		t.Errorf("role app is %d nodes, want one", n)
	}
	routes := routeNames(snapshotPaths(t, ctx, store))
	if !contains(routes, "app-vm -> app -> account-admin (effective)") {
		t.Errorf("routes %q: the instance should reach the escalation iam found on its role", routes)
	}
}

// An AWS role called "admin" and the ClusterRole "admin" every cluster ships were one node,
// so a namespace admin in Kubernetes appeared to reach the account's S3 data.
func TestAnAWSRoleIsNotAClusterRole(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, custodian.New(), `{"account_id":"123456789012","policies":[
	 {"resource":"aws.iam-role","resources":[{"RoleName":"admin","Arn":"arn:aws:iam::123456789012:role/admin",
	   "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}]},
	 {"resource":"aws.s3","resources":[{"Name":"customer-exports","Tags":[{"Key":"classification","Value":"pii"}]}]}]}`, ingestion.Options{})
	applyBody(t, ctx, store, k8s.New(), `[
	 {"kind":"Service","metadata":{"name":"web-lb","namespace":"web"},"spec":{"type":"LoadBalancer","selector":{"app":"web"}}},
	 {"kind":"Pod","metadata":{"name":"web-1","namespace":"web","labels":{"app":"web"}},"spec":{"serviceAccountName":"web-sa"}},
	 {"kind":"RoleBinding","metadata":{"name":"web-sa-admin","namespace":"web"},"roleRef":{"kind":"ClusterRole","name":"admin"},
	  "subjects":[{"kind":"ServiceAccount","name":"web-sa","namespace":"web"}]}]`, ingestion.Options{})

	for _, r := range routeNames(snapshotPaths(t, ctx, store)) {
		if strings.HasSuffix(r, "customer-exports") {
			t.Errorf("a Kubernetes route reached AWS data through a role that only shares a name: %s", r)
		}
	}
}

// Custodian keyed an instance on its id alone and the AWS connector's feed on its account,
// so the same instance was two nodes when both ran.
func TestCustodianAndTheAWSFeedDescribeOneInstance(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, cloudnet.New(), `{"provider":"aws","security_groups":[],
	 "instances":[{"InstanceId":"i-web","Tags":[{"Key":"Name","Value":"web-tier"}]}]}`,
		ingestion.Options{Account: "123456789012"})
	applyBody(t, ctx, store, custodian.New(), `{"account_id":"123456789012","policies":[
	 {"resource":"aws.ec2","resources":[{"InstanceId":"i-web","Tags":[{"Key":"Name","Value":"web-tier"}]}]}]}`, ingestion.Options{})

	if n := nodesNamed(t, ctx, store, ontology.LabelVirtualMachine, "web-tier"); n != 1 {
		t.Errorf("instance i-web is %d nodes, want one", n)
	}
}

// An RDS identifier and a load balancer's name are unique only within an account, and
// Custodian keyed both without it, as it once keyed instances. With c7n-org exporting two
// accounts, account A's internet-facing web-alb and account B's internal one were a single
// public load balancer, and it led from the internet into B's instance, its administrator
// role and B's customer database. Each is now its own node, in its own account.
func TestCustodianKeepsTwoAccountsApart(t *testing.T) {
	bundle := func(account, scheme string) string {
		return `{"account_id":"` + account + `","policies":[
		 {"resource":"aws.elbv2","resources":[{"LoadBalancerName":"web-alb","Scheme":"` + scheme + `",
		   "Tags":[{"Key":"app","Value":"web"}]}]},
		 {"resource":"aws.ec2","resources":[{"InstanceId":"i-web","Tags":[{"Key":"app","Value":"web"}],
		   "IamInstanceProfile":{"Arn":"arn:aws:iam::` + account + `:instance-profile/ops"}}]},
		 {"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"ops",
		   "Arn":"arn:aws:iam::` + account + `:instance-profile/ops",
		   "Roles":[{"RoleName":"ops","Arn":"arn:aws:iam::` + account + `:role/ops"}]}]},
		 {"resource":"aws.iam-role","resources":[{"RoleName":"ops","Arn":"arn:aws:iam::` + account + `:role/ops",
		   "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess",
		     "PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}]},
		 {"resource":"aws.rds","resources":[{"DBInstanceIdentifier":"prod-db",
		   "Tags":[{"Key":"classification","Value":"pii"}]}]}]}`
	}
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, custodian.New(), bundle("111111111111", "internet-facing"), ingestion.Options{})
	applyBody(t, ctx, store, custodian.New(), bundle("222222222222", "internal"), ingestion.Options{})

	if n := nodesNamed(t, ctx, store, ontology.LabelLoadBalancer, "web-alb"); n != 2 {
		t.Errorf("web-alb in two accounts is %d nodes, want two", n)
	}
	if n := nodesNamed(t, ctx, store, ontology.LabelDatabase, "prod-db"); n != 2 {
		t.Errorf("prod-db in two accounts is %d nodes, want two", n)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reached := map[string]bool{}
	for _, p := range analyzer.FindCriticalPaths(snap) {
		for _, n := range p.Nodes {
			if acct, _ := n.Properties[ontology.PropAccount].(string); acct != "" {
				reached[acct] = true
			}
		}
	}
	if !reached["111111111111"] {
		t.Error("account A's public load balancer must still lead to its own database")
	}
	if reached["222222222222"] {
		t.Error("a route from the internet entered account B, whose load balancer is internal")
	}

	// A classification names its database's account, and lands on that one only.
	applyBody(t, ctx, store, dataclass.New(), `{"source":"macie","records":[
	 {"asset":"prod-db","label":"Database","kind":"phi","account":"222222222222"}]}`, ingestion.Options{})
	snap, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snap.Nodes {
		if n.Label != ontology.LabelDatabase {
			continue
		}
		classified := n.Properties[ontology.PropClassification] == "phi"
		if acct := n.Properties[ontology.PropAccount]; classified != (acct == "222222222222") {
			t.Errorf("database in account %v classified=%v: the finding names account 222222222222", acct, classified)
		}
	}
}

// The cluster and the account around it are one estate to an attacker (OWASP Kubernetes
// Top 10, K08): a pod's ServiceAccount assumes an IAM role (IRSA), a pod that escapes
// holds its node's EC2 instance and the role it runs with, and an IAM identity mapped in
// aws-auth is a cluster identity. The engine drew the two graphs side by side and no
// route crossed between them.
func TestRoutesCrossBetweenClusterAndAccount(t *testing.T) {
	const acct = "123456789012"
	escalating := func(name, extraTrust string) string {
		return `{"RoleName":"` + name + `","Arn":"arn:aws:iam::` + acct + `:role/` + name + `",
		  "AssumeRolePolicyDocument":{"Statement":[` + extraTrust + `]},
		  "RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[
		    {"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}}]}`
	}
	const openGitHub = `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::` + acct + `:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity"}`
	iamBundle := `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[` +
		escalating("payments-irsa", "") + `,` + escalating("node-role", "") + `,` + escalating("ci-deployer", openGitHub) + `]}`
	const network = `{"provider":"aws","security_groups":[],
	  "instances":[{"InstanceId":"i-0node","IamInstanceProfile":{"Arn":"arn:aws:iam::` + acct + `:instance-profile/node"}}],
	  "instance_profiles":[{"Arn":"arn:aws:iam::` + acct + `:instance-profile/node",
	    "Roles":[{"Arn":"arn:aws:iam::` + acct + `:role/node-role","RoleName":"node-role"}]}]}`
	dump := func(privileged bool) string {
		return `{"kind":"List","items":[
	  {"kind":"Ingress","metadata":{"name":"web","namespace":"prod"},
	   "spec":{"rules":[{"http":{"paths":[{"backend":{"service":{"name":"web"}}}]}}]}},
	  {"kind":"Service","metadata":{"name":"web","namespace":"prod"},"spec":{"selector":{"app":"web"}}},
	  {"kind":"Pod","metadata":{"name":"web-1","namespace":"prod","labels":{"app":"web"}},
	   "spec":{"nodeName":"ip-10-0-1-5","serviceAccountName":"payments",
	     "containers":[{"name":"web","image":"web:1","securityContext":{"privileged":` + fmt.Sprint(privileged) + `}}]}},
	  {"kind":"ServiceAccount","metadata":{"name":"payments","namespace":"prod",
	   "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::` + acct + `:role/payments-irsa"}}},
	  {"kind":"Node","metadata":{"name":"ip-10-0-1-5"},"spec":{"providerID":"aws:///eu-west-1a/i-0node"}},
	  {"kind":"ConfigMap","metadata":{"name":"aws-auth","namespace":"kube-system"},"data":{
	   "mapRoles":"- rolearn: arn:aws:iam::` + acct + `:role/ci-deployer\n  username: ci\n  groups:\n    - system:masters\n"}}
	]}`
	}

	// The path finder keeps the best route per entry and target, so the escape (when the
	// pod can escape) outranks IRSA to account-admin: each is checked where it is the best.
	for _, c := range []struct {
		privileged bool
		want       []string
	}{
		{false, []string{
			"web -> web -> web-1 -> prod/payments -> payments-irsa -> account-admin (effective)", // IRSA
			"GitHub Actions (any repository) -> ci-deployer -> cluster-admin (effective)",        // aws-auth
		}},
		{true, []string{
			"web -> web -> web-1 -> i-0node -> node-role -> account-admin (effective)", // escape to the node
		}},
	} {
		ctx := context.Background()
		store := memory.New()
		applyBody(t, ctx, store, iam.New(), iamBundle, ingestion.Options{})
		applyBody(t, ctx, store, cloudnet.New(), network, ingestion.Options{Account: acct})
		applyBody(t, ctx, store, k8s.New(), dump(c.privileged), ingestion.Options{Account: acct})
		snap, err := store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		routes := map[string]bool{}
		for _, r := range routeNames(analyzer.FindCriticalPaths(snap)) {
			routes[r] = true
		}
		for _, want := range c.want {
			if !routes[want] {
				t.Errorf("privileged=%v: missing route %q among %v", c.privileged, want, routes)
			}
		}
	}
}

// EKS Pod Identity and access entries live in the EKS API, not in the cluster's objects,
// so a dump cannot show them: a pod got out to an IAM role, and an IAM principal got in as
// cluster-admin, without either step on the graph. The eks collector draws them, keyed to
// meet a dump sent with ?cluster=<the EKS name>.
func TestEKSAccessJoinsClusterAndAccount(t *testing.T) {
	const acct = "123456789012"
	role := func(name, trust string) string {
		return `{"RoleName":"` + name + `","Arn":"arn:aws:iam::` + acct + `:role/` + name + `",
		  "AssumeRolePolicyDocument":{"Statement":[` + trust + `]},
		  "RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[
		    {"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}}]}`
	}
	const openGitHub = `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::` + acct + `:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity"}`
	iamBundle := `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[` +
		role("payments-pi", "") + `,` + role("ci-deployer", openGitHub) + `,` + role("dev", "") + `]}`
	const dump = `{"kind":"List","items":[
	  {"kind":"Ingress","metadata":{"name":"web","namespace":"prod"},
	   "spec":{"rules":[{"http":{"paths":[{"backend":{"service":{"name":"web"}}}]}}]}},
	  {"kind":"Service","metadata":{"name":"web","namespace":"prod"},"spec":{"selector":{"app":"web"}}},
	  {"kind":"Pod","metadata":{"name":"web-1","namespace":"prod","labels":{"app":"web"}},
	   "spec":{"serviceAccountName":"payments","containers":[{"name":"web","image":"web:1"}]}},
	  {"kind":"ServiceAccount","metadata":{"name":"payments","namespace":"prod"}}]}`
	const access = `{"clusters":[{"name":"prod-eu",
	  "podIdentityAssociations":[{"namespace":"prod","serviceAccount":"payments","roleArn":"arn:aws:iam::` + acct + `:role/payments-pi"}],
	  "accessEntries":[
	    {"principalArn":"arn:aws:iam::` + acct + `:role/ci-deployer","accessPolicies":[
	      {"policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy","accessScope":{"type":"cluster"}}]},
	    {"principalArn":"arn:aws:iam::` + acct + `:role/dev","accessPolicies":[
	      {"policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy","accessScope":{"type":"namespace"}}]},
	    {"principalArn":"arn:aws:iam::` + acct + `:role/viewer","accessPolicies":[
	      {"policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy","accessScope":{"type":"cluster"}}]}]}]}`

	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, iam.New(), iamBundle, ingestion.Options{})
	applyBody(t, ctx, store, k8s.New(), dump, ingestion.Options{Cluster: "prod-eu"})
	applyBody(t, ctx, store, eks.New(), access, ingestion.Options{})
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, r := range routeNames(analyzer.FindCriticalPaths(snap)) {
		routes[r] = true
	}
	for _, want := range []string{
		"web -> web -> web-1 -> prod/payments -> payments-pi -> account-admin (effective)",     // Pod Identity
		"GitHub Actions (any repository) -> ci-deployer -> cluster-admin (effective, prod-eu)", // access entry
	} {
		if !routes[want] {
			t.Errorf("missing route %q among %v", want, routes)
		}
	}
	byID := snap.NodeByID()
	dev := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+acct+":role/dev")
	viewer := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+acct+":role/viewer")
	escalates := false
	for _, e := range snap.Edges {
		if e.From == dev && e.Type == ontology.EdgeAssumes {
			for _, e2 := range snap.Edges {
				escalates = escalates || (e2.From == e.To && e2.Type == ontology.EdgeCanEscalateTo &&
					strings.HasPrefix(byID[e2.To].Name, "cluster-admin"))
			}
		}
		if e.From == viewer {
			t.Errorf("a view-only access entry is no way anywhere, got %s to %s", e.Type, byID[e.To].Name)
		}
	}
	if !escalates {
		t.Error("an edit access entry reads secrets, a way to cluster-admin the k8s collector weighs")
	}
}

// A Lambda function anyone can invoke is an entry point, and its execution role is in its
// environment: the route continues into the role. The engine did not read Lambda at all.
// The verdict is written either way, so removing the public URL retracts it.
func TestALambdaFunctionAnyoneCanInvokeIsAnEntryPoint(t *testing.T) {
	const acct = "123456789012"
	iamBundle := `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[
	 {"RoleName":"orders-exec","Arn":"arn:aws:iam::` + acct + `:role/orders-exec","AssumeRolePolicyDocument":{"Statement":[]},
	  "RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
	   {"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"}]}}]}]}`
	fn := func(name, url, policy string) string {
		s := `{"FunctionName":"` + name + `","FunctionArn":"arn:aws:lambda:eu-west-1:` + acct + `:function:` + name + `",
		  "Role":"arn:aws:iam::` + acct + `:role/orders-exec"`
		if url != "" {
			s += `,"Url":{"AuthType":"` + url + `","FunctionUrl":"https://x.lambda-url.eu-west-1.on.aws/"}`
		}
		if policy != "" {
			s += `,"Policy":` + policy
		}
		return s + `}`
	}
	const publicURL = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl",
	  "Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`
	const publicInvoke = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}`
	const oneAccount = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"lambda:InvokeFunctionUrl"}]}`
	// What the console writes for a URL without authentication since October 2025.
	const bothGrants = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl",
	  "Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}},
	  {"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Condition":{"Bool":{"lambda:InvokedViaFunctionUrl":"true"}}}]}`
	created := func(s, when string) string {
		return strings.Replace(s, `"FunctionUrl":`, `"CreationTime":"`+when+`","FunctionUrl":`, 1)
	}
	bundle := `{"functions":[` + strings.Join([]string{
		fn("orders-api", "NONE", publicURL), // open URL
		fn("reports", "AWS_IAM", ""),        // the URL asks for IAM credentials
		fn("billing", "", publicInvoke),     // any AWS principal may invoke it
		fn("internal", "NONE", oneAccount),  // URL without auth, but the policy names one account
		// A URL created in 2026 with the URL grant alone answers 403: the real-account lab saw it.
		created(fn("new-url-grant-only", "NONE", publicURL), "2026-10-02T15:04:05.000+0000"),
		created(fn("new-both-grants", "NONE", bothGrants), "2026-10-02T15:04:05.000+0000"),
		created(fn("old-url-grant-only", "NONE", publicURL), "2024-03-01T09:00:00.000+0000"),
		fn("both-grants-no-url", "", bothGrants), // the URL is gone; the grants hold for no direct call
	}, ",") + `]}`

	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, iam.New(), iamBundle, ingestion.Options{})
	applyBody(t, ctx, store, lambda.New(), bundle, ingestion.Options{})
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exposed := map[string]bool{}
	for _, n := range snap.Nodes {
		if n.Label == ontology.LabelFunction {
			exposed[n.Name] = n.InternetExposed()
		}
	}
	for name, want := range map[string]bool{"orders-api": true, "reports": false, "billing": true, "internal": false,
		"new-url-grant-only": false, "new-both-grants": true, "old-url-grant-only": true, "both-grants-no-url": false} {
		if exposed[name] != want {
			t.Errorf("%s exposed = %v, want %v", name, exposed[name], want)
		}
	}
	routes := map[string]bool{}
	for _, r := range routeNames(analyzer.FindCriticalPaths(snap)) {
		routes[r] = true
	}
	if !routes["orders-api -> orders-exec -> account-admin (effective)"] {
		t.Errorf("the open function's route into its role's escalation is missing: %v", routes)
	}

	// The public URL is removed: the next pull takes the function off the internet.
	applyBody(t, ctx, store, lambda.New(), `{"functions":[`+fn("orders-api", "", "")+`]}`, ingestion.Options{})
	snap, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snap.Nodes {
		if n.Name == "orders-api" && n.InternetExposed() {
			t.Error("orders-api lost its public URL and is still exposed")
		}
	}
}

// aws-auth maps an IAM role into one cluster. Group nodes are shared across clusters on
// purpose, so the mapping must not reach the bindings another cluster gives the same group.
func TestAWSAuthHoldsInItsOwnCluster(t *testing.T) {
	bindDevs := func(withAuth bool) string {
		auth := ""
		if withAuth {
			auth = `,{"kind":"ConfigMap","metadata":{"name":"aws-auth","namespace":"kube-system"},"data":{
			  "mapRoles":"- rolearn: arn:aws:iam::1:role/dev\n  username: dev\n  groups: [devs]\n"}}`
		}
		return `{"kind":"List","items":[
		  {"kind":"ClusterRole","metadata":{"name":"team-admin"},"rules":[{"verbs":["*"],"resources":["*"],"apiGroups":["*"]}]},
		  {"kind":"ClusterRoleBinding","metadata":{"name":"devs-admin"},"roleRef":{"kind":"ClusterRole","name":"team-admin"},
		   "subjects":[{"kind":"Group","name":"devs"}]}` + auth + `]}`
	}
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, k8s.New(), bindDevs(true), ingestion.Options{Cluster: "a"})
	applyBody(t, ctx, store, k8s.New(), bindDevs(false), ingestion.Options{Cluster: "b"})
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := snap.NodeByID()
	dev := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::1:role/dev")
	reached := map[string]bool{}
	for _, e := range snap.Edges {
		if e.From == dev {
			reached[fmt.Sprint(byID[e.To].Properties["k8s_cluster"])] = true
		}
	}
	if !reached["a"] || reached["b"] {
		t.Errorf("the role mapped in cluster a reaches clusters %v, want only a", reached)
	}
}

// Exposure must be retractable. Properties accumulate across ingests, and the network
// source wrote internet_exposed only when it was true - so closing a security group left
// the instance exposed for good, and Custodian, which sees only a public address, could
// re-expose an instance the network source had just cleared. The network verdict is now
// written either way and decides, in whatever order the two arrive.
func TestExposureFollowsTheNetworkVerdict(t *testing.T) {
	network := func(cidr string) string {
		return `{"provider":"aws","security_groups":[{"GroupId":"sg-1","IpPermissions":[
		  {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"` + cidr + `"}]}]}],
		  "instances":[{"InstanceId":"i-1","SecurityGroups":[{"GroupId":"sg-1"}],"Tags":[{"Key":"Name","Value":"box"}]}]}`
	}
	const publicIP = `{"account_id":"123456789012","policies":[{"resource":"aws.ec2","resources":[
	  {"InstanceId":"i-1","PublicIpAddress":"203.0.113.9","Tags":[{"Key":"Name","Value":"box"}]}]}]}`
	exposure := func(store *memory.Store) (bool, string) {
		snap, err := store.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snap.Nodes {
			if n.Label == ontology.LabelVirtualMachine {
				ports, _ := n.Properties["exposed_ports"].(string)
				return n.InternetExposed(), ports
			}
		}
		t.Fatal("no instance")
		return false, ""
	}
	acct := ingestion.Options{Account: "123456789012"}

	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, cloudnet.New(), network("0.0.0.0/0"), acct)
	if exposed, ports := exposure(store); !exposed || ports != "tcp/22" {
		t.Fatalf("open on 22: exposed=%v on %q", exposed, ports)
	}
	applyBody(t, ctx, store, cloudnet.New(), network("10.0.0.0/8"), acct)
	if exposed, ports := exposure(store); exposed || ports != "" {
		t.Errorf("the group was closed to the internet, and the instance is still exposed=%v on %q", exposed, ports)
	}

	for _, custodianLast := range []bool{false, true} {
		store := memory.New()
		if custodianLast {
			applyBody(t, ctx, store, cloudnet.New(), network("10.0.0.0/8"), acct)
			applyBody(t, ctx, store, custodian.New(), publicIP, ingestion.Options{})
		} else {
			applyBody(t, ctx, store, custodian.New(), publicIP, ingestion.Options{})
			applyBody(t, ctx, store, cloudnet.New(), network("10.0.0.0/8"), acct)
		}
		if exposed, _ := exposure(store); exposed {
			t.Errorf("Custodian last=%v: a public address does not expose an instance whose groups the network source found closed", custodianLast)
		}
	}
}

// A role that trusts GitHub Actions without pinning the subject to an owner can be assumed
// by a workflow in any repository on GitHub - a door from the internet the engine did not
// see, since it read only AWS and Service principals. The route now starts there.
func TestAnOpenGitHubTrustIsAnEntryPoint(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, iam.New(), `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[
	 {"RoleName":"deploy","Arn":"arn:aws:iam::123456789012:role/deploy",
	  "AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow",
	    "Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
	    "Action":"sts:AssumeRoleWithWebIdentity",
	    "Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]},
	  "RolePolicyList":[{"PolicyName":"deploy","PolicyDocument":{"Statement":[
	    {"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}}]}]}`, ingestion.Options{})
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routes := routeNames(analyzer.FindCriticalPaths(snap))
	want := "GitHub Actions (any repository) -> deploy -> account-admin (effective)"
	found := false
	for _, r := range routes {
		found = found || r == want
	}
	if !found {
		t.Errorf("routes %v, want %q", routes, want)
	}
}

// An RDS identifier and a load balancer's name are unique per account AND Region, and
// 1.28.2 scoped them by account only: prod-db in eu-west-1 and in us-east-1 of one account
// were still one database. And within one export, a load balancer was linked to every
// instance sharing its app tag, in any Region, though a load balancer only routes inside
// its own: an internet-facing ALB in eu-west-1 led into an instance in us-east-1. The
// Region comes from the resources themselves - an ARN, an availability zone.
func TestCustodianKeepsTwoRegionsApart(t *testing.T) {
	const acct = "111111111111"
	instance := func(id, zone string) string {
		return `{"InstanceId":"` + id + `","Placement":{"AvailabilityZone":"` + zone + `"},
		  "Tags":[{"Key":"app","Value":"web"},{"Key":"Name","Value":"` + id + `"}],
		  "IamInstanceProfile":{"Arn":"arn:aws:iam::` + acct + `:instance-profile/ops"}}`
	}
	db := func(region string) string {
		return `{"DBInstanceIdentifier":"prod-db","DBInstanceArn":"arn:aws:rds:` + region + `:` + acct + `:db:prod-db",
		  "Tags":[{"Key":"classification","Value":"pii"}]}`
	}
	lb := func(region, scheme string) string {
		return `{"LoadBalancerName":"web-alb","Scheme":"` + scheme + `","Tags":[{"Key":"app","Value":"web"}],
		  "LoadBalancerArn":"arn:aws:elasticloadbalancing:` + region + `:` + acct + `:loadbalancer/app/web-alb/0123456789abcdef"}`
	}
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, custodian.New(), `{"account_id":"`+acct+`","policies":[
	 {"resource":"aws.elbv2","resources":[`+lb("eu-west-1", "internet-facing")+`,`+lb("us-east-1", "internal")+`]},
	 {"resource":"aws.ec2","resources":[`+instance("i-eu", "eu-west-1a")+`,`+instance("i-us", "us-east-1b")+`]},
	 {"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"ops","Arn":"arn:aws:iam::`+acct+`:instance-profile/ops",
	   "Roles":[{"RoleName":"ops","Arn":"arn:aws:iam::`+acct+`:role/ops"}]}]},
	 {"resource":"aws.iam-role","resources":[{"RoleName":"ops","Arn":"arn:aws:iam::`+acct+`:role/ops",
	   "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}]},
	 {"resource":"aws.rds","resources":[`+db("eu-west-1")+`,`+db("us-east-1")+`]}]}`, ingestion.Options{})

	if n := nodesNamed(t, ctx, store, ontology.LabelDatabase, "prod-db"); n != 2 {
		t.Errorf("prod-db in two Regions is %d nodes, want two", n)
	}
	if n := nodesNamed(t, ctx, store, ontology.LabelLoadBalancer, "web-alb"); n != 2 {
		t.Errorf("web-alb in two Regions is %d nodes, want two", n)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The path finder keeps the best route per entry and target, so a route through i-us
	// would hide behind the one through i-eu: check the links themselves.
	byID := snap.NodeByID()
	zoneOf := map[string]string{"i-eu": "eu-west-1", "i-us": "us-east-1"}
	for _, e := range snap.Edges {
		if e.Type != ontology.EdgeRoutesTo {
			continue
		}
		lb, vm := byID[e.From], byID[e.To]
		if lb.Properties["region"] != zoneOf[vm.Name] {
			t.Errorf("the load balancer in %v routes to %s, in %s", lb.Properties["region"], vm.Name, zoneOf[vm.Name])
		}
	}
	throughEU := false
	for _, p := range analyzer.FindCriticalPaths(snap) {
		for _, n := range p.Nodes {
			switch n.Name {
			case "i-us":
				t.Errorf("a route entered us-east-1, whose load balancer is internal: %v", routeNames([]analyzer.AttackPath{p}))
			case "i-eu":
				throughEU = true
			}
		}
	}
	if !throughEU {
		t.Error("the internet-facing load balancer in eu-west-1 must still lead to its own instance")
	}

	applyBody(t, ctx, store, dataclass.New(), `{"source":"classifier","records":[
	 {"asset":"prod-db","label":"Database","kind":"phi","account":"`+acct+`","region":"us-east-1"}]}`, ingestion.Options{})
	snap, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snap.Nodes {
		if n.Label == ontology.LabelDatabase {
			classified := n.Properties[ontology.PropClassification] == "phi"
			if region := n.Properties["region"]; classified != (region == "us-east-1") {
				t.Errorf("database in %v classified=%v: the finding names us-east-1", region, classified)
			}
		}
	}
}

// Falco keyed a container by its own name; the Kubernetes dump keys the pod it runs in as
// namespace/pod. The alert sat on a node of its own and no route through the pod was ever
// marked runtime-confirmed - with a real cluster dump. The demo hid it: its topology was
// written by hand with Falco's key. In a named cluster, both carry the cluster.
func TestFalcoAlertsLandOnTheKubernetesPod(t *testing.T) {
	dump, err := os.ReadFile("../../testdata/k8s-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	const alert = `[{"rule":"Terminal shell in container","priority":"Critical","output":"shell",
	 "output_fields":{"container.name":"payments","k8s.pod.name":"payments-7d9f","k8s.ns.name":"prod"}}]`
	for _, cluster := range []string{"", "prod-eu"} {
		ctx := context.Background()
		store := memory.New()
		applyBody(t, ctx, store, k8s.New(), string(dump), ingestion.Options{Cluster: cluster})
		applyBody(t, ctx, store, falco.New(), alert, ingestion.Options{Cluster: cluster})
		snap, err := store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pods := 0
		for _, n := range snap.Nodes {
			if n.Label == ontology.LabelContainer && strings.HasPrefix(n.Name, "payments") {
				pods++
			}
		}
		if pods != 1 {
			t.Errorf("cluster %q: the alerted pod is %d nodes, want one", cluster, pods)
		}
		confirmed := 0
		for _, p := range analyzer.FindCriticalPaths(snap) {
			through := false
			for _, n := range p.Nodes {
				through = through || n.Name == "payments-7d9f"
			}
			if through && !p.RuntimeConfirmed {
				t.Errorf("cluster %q: a route through the alerted pod is not runtime-confirmed: %v",
					cluster, routeNames([]analyzer.AttackPath{p}))
			}
			if through {
				confirmed++
			}
		}
		if confirmed == 0 {
			t.Errorf("cluster %q: no route through the alerted pod", cluster)
		}
	}
}

// Trivy and an SBOM both list what an image ships, and the SBOM was meant to converge
// with Trivy's nodes and complete the bill with the components that have no CVE. It never
// did: it keyed "name:version" where Trivy keys name and version apart, and named a Maven
// package by its artifact where Trivy says groupId:artifactId. Log4j was two nodes, and the
// SBOM's never met the CVE Trivy found on it. The shapes below are the tools' own: Trivy's
// report and a CycloneDX document as syft writes it.
func TestTrivyAndTheSBOMDescribeOneLibrary(t *testing.T) {
	const scan = `{"ArtifactName":"payments-api:1.4.2","ArtifactType":"container_image","Results":[
	 {"Target":"Java","Class":"lang-pkgs","Type":"jar","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core",
	   "InstalledVersion":"2.14.1","Severity":"CRITICAL"}]}]}`
	const sbom = `{"image":"payments-api:1.4.2","sbom":{"bomFormat":"CycloneDX","components":[
	 {"type":"library","group":"org.apache.logging.log4j","name":"log4j-core","version":"2.14.1",
	  "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
	 {"type":"library","group":"org.slf4j","name":"slf4j-api","version":"1.7.36",
	  "purl":"pkg:maven/org.slf4j/slf4j-api@1.7.36"}]}}`
	for _, sbomLast := range []bool{false, true} {
		ctx := context.Background()
		store := memory.New()
		writeScan := func() { applyBody(t, ctx, store, trivy.New(), scan, ingestion.Options{}) }
		writeSBOM := func() { applyBody(t, ctx, store, supplychain.New(), sbom, ingestion.Options{}) }
		if sbomLast {
			writeScan()
			writeSBOM()
		} else {
			writeSBOM()
			writeScan()
		}
		snap, err := store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var log4j []ontology.Node
		slf4j := 0
		for _, n := range snap.Nodes {
			switch {
			case n.Label == ontology.LabelLibrary && strings.Contains(n.Name, "log4j-core"):
				log4j = append(log4j, n)
			case n.Label == ontology.LabelLibrary && strings.Contains(n.Name, "slf4j-api"):
				slf4j++
			}
		}
		if len(log4j) != 1 {
			t.Fatalf("SBOM last=%v: log4j-core is %d nodes, want one: %+v", sbomLast, len(log4j), log4j)
		}
		if slf4j != 1 {
			t.Errorf("SBOM last=%v: the component with no CVE must still complete the bill", sbomLast)
		}
		var affects, depends []ontology.Edge
		for _, e := range snap.Edges {
			switch {
			case e.Type == ontology.EdgeAffects && e.From == log4j[0].ID:
				affects = append(affects, e)
			case e.Type == ontology.EdgeDependsOn && e.To == log4j[0].ID:
				depends = append(depends, e)
			}
		}
		if len(affects) != 1 {
			t.Errorf("SBOM last=%v: the library both feeds describe must carry the CVE, got %d AFFECTS", sbomLast, len(affects))
		}
		if len(depends) != 1 || depends[0].ExploitProbability != ingestion.DependsOnProb {
			t.Errorf("SBOM last=%v: image --DEPENDS_ON--> log4j-core = %+v, want one edge at %.2f whichever feed came last",
				sbomLast, depends, ingestion.DependsOnProb)
		}
	}
}

// Once Custodian and the AWS network feed met on one instance and one role, they wrote the
// same instance --ASSUMES--> role step with different probabilities, and the last one
// written won: 0.6 or 0.8 for an instance requiring IMDSv2, and 0.4 or 0.9 when Custodian
// had to guess the role and the feed stated it. Both now score the step from the
// instance's IMDS setting, and a guess never replaces a fact, so the order is irrelevant.
func TestTheAWSSourcesAgreeOnTheInstanceRoleStep(t *testing.T) {
	const profile = `"IamInstanceProfile":{"Arn":"arn:aws:iam::123456789012:instance-profile/app"}`
	network := func(tokens string) string {
		return `{"provider":"aws","security_groups":[],
		 "instances":[{"InstanceId":"i-web",` + profile + `,"MetadataOptions":{"HttpTokens":"` + tokens + `"}}],
		 "instance_profiles":[{"Arn":"arn:aws:iam::123456789012:instance-profile/app",
		   "Roles":[{"Arn":"arn:aws:iam::123456789012:role/app","RoleName":"app"}]}]}`
	}
	custodianExport := func(tokens string, listsProfiles bool) string {
		body := `{"account_id":"123456789012","policies":[
		 {"resource":"aws.ec2","resources":[{"InstanceId":"i-web",` + profile + `,"MetadataOptions":{"HttpTokens":"` + tokens + `"}}]}`
		if listsProfiles {
			body += `,{"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"app",
			  "Arn":"arn:aws:iam::123456789012:instance-profile/app",
			  "Roles":[{"RoleName":"app","Arn":"arn:aws:iam::123456789012:role/app"}]}]}`
		}
		return body + `]}`
	}
	cases := []struct {
		name          string
		tokens        string
		listsProfiles bool
		want          float64
	}{
		{"both state it, IMDSv2 required", "required", true, 0.6},
		{"Custodian guesses, the feed states it", "optional", false, 0.9},
	}
	for _, c := range cases {
		for _, custodianLast := range []bool{false, true} {
			ctx := context.Background()
			store := memory.New()
			writeNetwork := func() {
				applyBody(t, ctx, store, cloudnet.New(), network(c.tokens), ingestion.Options{Account: "123456789012"})
			}
			writeCustodian := func() {
				applyBody(t, ctx, store, custodian.New(), custodianExport(c.tokens, c.listsProfiles), ingestion.Options{})
			}
			if custodianLast {
				writeNetwork()
				writeCustodian()
			} else {
				writeCustodian()
				writeNetwork()
			}
			snap, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var steps []ontology.Edge
			for _, e := range snap.Edges {
				if e.Type == ontology.EdgeAssumes {
					steps = append(steps, e)
				}
			}
			if len(steps) != 1 || steps[0].ExploitProbability != c.want || graph.Inferred(steps[0]) {
				t.Errorf("%s, Custodian last=%v: steps %+v, want one stated step at p=%.1f",
					c.name, custodianLast, steps, c.want)
			}
		}
	}
}

// Every cluster has a prod namespace and a cluster-admin. Without the cluster in the ids,
// an exposed workload in one cluster reached the cluster-admin of another, through a
// service account that only shared its name.
func TestRoutesDoNotCrossClusters(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, k8s.New(), `[
	 {"kind":"Service","metadata":{"name":"web-svc","namespace":"prod"},"spec":{"type":"ClusterIP","selector":{"app":"web"}}},
	 {"kind":"Pod","metadata":{"name":"web-1","namespace":"prod","labels":{"app":"web"}},"spec":{"serviceAccountName":"web-sa"}},
	 {"kind":"ClusterRoleBinding","metadata":{"name":"web-sa-admin"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
	  "subjects":[{"kind":"ServiceAccount","name":"web-sa","namespace":"prod"}]}]`, ingestion.Options{Cluster: "a"})
	applyBody(t, ctx, store, k8s.New(), `[
	 {"kind":"Service","metadata":{"name":"web-lb","namespace":"prod"},"spec":{"type":"LoadBalancer","selector":{"app":"web"}}},
	 {"kind":"Pod","metadata":{"name":"web-1","namespace":"prod","labels":{"app":"web"}},"spec":{"serviceAccountName":"web-sa"}},
	 {"kind":"ClusterRoleBinding","metadata":{"name":"web-sa-view"},"roleRef":{"kind":"ClusterRole","name":"view"},
	  "subjects":[{"kind":"ServiceAccount","name":"web-sa","namespace":"prod"}]}]`, ingestion.Options{Cluster: "b"})

	if routes := routeNames(snapshotPaths(t, ctx, store)); len(routes) != 0 {
		t.Errorf("cluster b is exposed but its web-sa can only read, and cluster a's admin is not exposed; got %q", routes)
	}
}

// One cluster, two namespaces, two Roles named "deployer": only the one in ci can create
// pods. Keyed on the name alone, the one in web inherited that and a route to cluster-admin.
func TestNamespacedRolesDoNotLendTheirRules(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, k8s.New(), `[
	 {"kind":"Role","metadata":{"name":"deployer","namespace":"ci"},"rules":[{"verbs":["create"],"resources":["pods"]}]},
	 {"kind":"RoleBinding","metadata":{"name":"b1","namespace":"ci"},"roleRef":{"kind":"Role","name":"deployer"},
	  "subjects":[{"kind":"ServiceAccount","name":"builder","namespace":"ci"}]},
	 {"kind":"Role","metadata":{"name":"deployer","namespace":"web"},"rules":[{"verbs":["get"],"resources":["configmaps"]}]},
	 {"kind":"RoleBinding","metadata":{"name":"b2","namespace":"web"},"roleRef":{"kind":"Role","name":"deployer"},
	  "subjects":[{"kind":"ServiceAccount","name":"web-sa","namespace":"web"}]},
	 {"kind":"Service","metadata":{"name":"web-lb","namespace":"web"},"spec":{"type":"LoadBalancer","selector":{"app":"web"}}},
	 {"kind":"Pod","metadata":{"name":"web-1","namespace":"web","labels":{"app":"web"}},"spec":{"serviceAccountName":"web-sa"}}]`,
		ingestion.Options{})

	if routes := routeNames(snapshotPaths(t, ctx, store)); len(routes) != 0 {
		t.Errorf("web's deployer only reads config maps; got %q", routes)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The commonest AWS shape: a public load balancer, the instance behind it in a private
// subnet. The network feed rightly calls the instance unexposed, and before load balancers
// were read the route stopped there - a false negative where routes are most common. The
// load balancer is the way in, and Cloud Custodian's report of it lands on the same node.
func TestALoadBalancerIsTheWayIn(t *testing.T) {
	const acct = "123456789012"
	const lbArn = "arn:aws:elasticloadbalancing:eu-west-1:" + acct + ":loadbalancer/app/web/1"
	iamBundle := `{"UserDetailList":[],"GroupDetailList":[],"Policies":[],"RoleDetailList":[
	 {"RoleName":"app-role","Arn":"arn:aws:iam::` + acct + `:role/app-role","AssumeRolePolicyDocument":{"Statement":[]},
	  "RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
	   {"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"}]}}]}]}`
	network := `{
	  "security_groups": [
	    { "GroupId": "sg-alb", "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-app", "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [ { "GroupId": "sg-alb" } ] } ] } ],
	  "instances": [ { "InstanceId": "i-app", "SubnetId": "subnet-priv", "PrivateIpAddress": "10.0.2.10",
	    "SecurityGroups": [ { "GroupId": "sg-app" } ], "Tags": [ { "Key": "Name", "Value": "app" } ],
	    "IamInstanceProfile": { "Arn": "arn:aws:iam::` + acct + `:instance-profile/app" }, "MetadataOptions": { "HttpTokens": "required" } } ],
	  "instance_profiles": [ { "Arn": "arn:aws:iam::` + acct + `:instance-profile/app",
	    "Roles": [ { "Arn": "arn:aws:iam::` + acct + `:role/app-role", "RoleName": "app-role" } ] } ],
	  "load_balancers": [ { "LoadBalancerArn": "` + lbArn + `", "LoadBalancerName": "web", "Type": "application",
	    "Scheme": "internet-facing", "SecurityGroups": [ "sg-alb" ], "AvailabilityZones": [ { "SubnetId": "subnet-pub" } ],
	    "Listeners": [ { "Protocol": "HTTPS", "Port": 443 } ],
	    "TargetGroups": [ { "TargetGroupArn": "tg-app", "TargetType": "instance", "Protocol": "HTTP", "Port": 8080, "Targets": [ { "Id": "i-app" } ] } ] } ],
	  "subnets": [ { "SubnetId": "subnet-pub", "RouteTableId": "rt-pub" }, { "SubnetId": "subnet-priv", "RouteTableId": "rt-priv" } ],
	  "route_tables": [ { "RouteTableId": "rt-pub", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1" } ] },
	                    { "RouteTableId": "rt-priv", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1" } ] } ]
	}`
	ctx := context.Background()
	store := memory.New()
	applyBody(t, ctx, store, iam.New(), iamBundle, ingestion.Options{})
	applyBody(t, ctx, store, cloudnet.New(), network, ingestion.Options{Account: acct})
	// Custodian reports the same load balancer - as aws.app-elb, Custodian's own name for
	// application and network load balancers - and it must land on the same node.
	custodianLB := `{"account_id":"` + acct + `","policies":[{"resource":"aws.app-elb","resources":[
	  {"LoadBalancerName":"web","LoadBalancerArn":"` + lbArn + `","Scheme":"internet-facing"}]}]}`
	evs, err := custodian.New().Parse(strings.NewReader(custodianLB), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	read := false
	for _, n := range evs[0].Nodes {
		read = read || (n.Label == ontology.LabelLoadBalancer &&
			n.ID == ingestion.RegionalID(ontology.LabelLoadBalancer, acct, "eu-west-1", "web"))
	}
	if !read {
		t.Error("Custodian's aws.app-elb load balancer is not read, or not keyed as the network feed keys it")
	}
	applyBody(t, ctx, store, custodian.New(), custodianLB, ingestion.Options{})
	if n := nodesNamed(t, ctx, store, ontology.LabelLoadBalancer, "web"); n != 1 {
		t.Errorf("the load balancer is %d nodes; the network feed and Custodian must describe one", n)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, r := range routeNames(analyzer.FindCriticalPaths(snap)) {
		routes[r] = true
	}
	if !routes["web -> app -> app-role -> account-admin (effective)"] {
		t.Errorf("the route through the load balancer into the private instance's role is missing: %v", routes)
	}
}
