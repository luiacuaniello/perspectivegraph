package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeEKS is one cluster with a Pod Identity association and two access entries. With
// denyPodIdentity it answers the Pod Identity calls as an account that granted only
// SecurityAudit does: access denied.
type fakeEKS struct{ denyPodIdentity bool }

func (fakeEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{Clusters: []string{"prod-eu"}}, nil
}

func (f fakeEKS) ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	if f.denyPodIdentity {
		return nil, errors.New("AccessDeniedException: not authorized to perform eks:ListPodIdentityAssociations")
	}
	return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
		{AssociationId: aws.String("a-1"), Namespace: aws.String("prod"), ServiceAccount: aws.String("payments")},
	}}, nil
}

func (fakeEKS) DescribePodIdentityAssociation(_ context.Context, in *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
		Namespace: aws.String("prod"), ServiceAccount: aws.String("payments"),
		RoleArn: aws.String("arn:aws:iam::123456789012:role/payments-pi")}}, nil
}

func (fakeEKS) ListAccessEntries(context.Context, *eks.ListAccessEntriesInput, ...func(*eks.Options)) (*eks.ListAccessEntriesOutput, error) {
	return &eks.ListAccessEntriesOutput{AccessEntries: []string{
		"arn:aws:iam::123456789012:role/ci-deployer", "arn:aws:iam::123456789012:role/viewer"}}, nil
}

func (fakeEKS) ListAssociatedAccessPolicies(_ context.Context, in *eks.ListAssociatedAccessPoliciesInput, _ ...func(*eks.Options)) (*eks.ListAssociatedAccessPoliciesOutput, error) {
	policy := "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
	if aws.ToString(in.PrincipalArn) == "arn:aws:iam::123456789012:role/ci-deployer" {
		policy = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
	}
	return &eks.ListAssociatedAccessPoliciesOutput{AssociatedAccessPolicies: []ekstypes.AssociatedAccessPolicy{
		{PolicyArn: aws.String(policy), AccessScope: &ekstypes.AccessScope{Type: ekstypes.AccessScopeTypeCluster}}}}, nil
}

// The connector reads each cluster's Pod Identity associations and access entries, and a
// refusal of the Pod Identity calls - outside SecurityAudit - costs only those.
func TestSDKReadsEKSAccess(t *testing.T) {
	for _, deny := range []bool{false, true} {
		events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}, eks: fakeEKS{denyPodIdentity: deny}}).Collect(context.Background())
		if err != nil {
			t.Fatalf("deny=%v: collect: %v", deny, err)
		}
		var podIdentity, clusterAdmin bool
		byID := map[string]ontology.Node{}
		for _, ev := range events {
			for _, n := range ev.Nodes {
				byID[n.ID] = n
			}
		}
		for _, ev := range events {
			if ev.Source != "eks" {
				continue
			}
			for _, e := range ev.Edges {
				from, to := byID[e.From], byID[e.To]
				switch {
				case from.Name == "prod/payments" && to.Name == "payments-pi":
					podIdentity = true
				case from.Name == "ci-deployer" && to.Name == "cluster-admin (effective, prod-eu)":
					clusterAdmin = true
				case from.Name == "viewer":
					t.Errorf("deny=%v: a view-only access entry drew %s to %s", deny, e.Type, to.Name)
				}
			}
		}
		if podIdentity == deny {
			t.Errorf("deny=%v: Pod Identity edge drawn = %v", deny, podIdentity)
		}
		if !clusterAdmin {
			t.Errorf("deny=%v: the cluster-admin access entry must come through either way", deny)
		}
	}
}
