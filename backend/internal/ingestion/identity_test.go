package ingestion_test

// The same thing reported by two sources must be one node, and two things that merely
// share a name must stay two. Each case below was a wrong route, found by running the
// sources together: a role and an instance seen by Custodian and by the AWS feeds, an AWS
// role and a Kubernetes ClusterRole of the same name, two clusters, two namespaces.

import (
	"context"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
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
