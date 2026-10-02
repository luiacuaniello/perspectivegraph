package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

// eksAPI is the slice of EKS the connector reads: which IAM roles each cluster's pods get
// (Pod Identity) and which IAM principals get into it, with which access policies.
type eksAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(context.Context, *eks.DescribePodIdentityAssociationInput, ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
	ListAccessEntries(context.Context, *eks.ListAccessEntriesInput, ...func(*eks.Options)) (*eks.ListAccessEntriesOutput, error)
	ListAssociatedAccessPolicies(context.Context, *eks.ListAssociatedAccessPoliciesInput, ...func(*eks.Options)) (*eks.ListAssociatedAccessPoliciesOutput, error)
}

// The EKS bundle, in the shape the eks collector reads.
type eksBundle struct {
	Clusters []eksCluster `json:"clusters"`
}

type eksCluster struct {
	Name                    string           `json:"name"`
	PodIdentityAssociations []eksPodIdentity `json:"podIdentityAssociations,omitempty"`
	AccessEntries           []eksAccessEntry `json:"accessEntries,omitempty"`
}

type eksPodIdentity struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	RoleArn        string `json:"roleArn"`
}

type eksAccessEntry struct {
	PrincipalArn   string            `json:"principalArn"`
	AccessPolicies []eksAccessPolicy `json:"accessPolicies,omitempty"`
}

type eksAccessPolicy struct {
	PolicyArn   string `json:"policyArn"`
	AccessScope struct {
		Type string `json:"type"`
	} `json:"accessScope"`
}

// fetchEKS reads every cluster in the region. Access entries are inside SecurityAudit;
// Pod Identity is not - it takes eks:ListPodIdentityAssociations and
// eks:DescribePodIdentityAssociation - so a refusal there is logged and the rest of the
// cluster still comes back: one missing permission must not hide every access entry.
func (t *sdkTransport) fetchEKS(ctx context.Context) ([]byte, error) {
	if t.eks == nil {
		return nil, nil
	}
	var b eksBundle
	var next *string
	for {
		out, err := t.eks.ListClusters(ctx, &eks.ListClustersInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("list eks clusters: %w", err)
		}
		for _, name := range out.Clusters {
			cl := eksCluster{Name: name}
			pods, err := t.podIdentities(ctx, name)
			if err != nil {
				slog.Warn("aws connector: Pod Identity associations not read; grant eks:ListPodIdentityAssociations "+
					"and eks:DescribePodIdentityAssociation to see the IAM roles this cluster's pods assume",
					"cluster", name, "err", err)
			}
			cl.PodIdentityAssociations = pods
			if cl.AccessEntries, err = t.accessEntries(ctx, name); err != nil {
				return nil, fmt.Errorf("access entries of eks cluster %s: %w", name, err)
			}
			b.Clusters = append(b.Clusters, cl)
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	if len(b.Clusters) == 0 {
		return nil, nil // no clusters in this region: nothing to describe, nothing to retract
	}
	return json.Marshal(b)
}

func (t *sdkTransport) podIdentities(ctx context.Context, cluster string) ([]eksPodIdentity, error) {
	var out []eksPodIdentity
	var next *string
	for {
		page, err := t.eks.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: aws.String(cluster), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, a := range page.Associations {
			// The summary names the service account but not the role: that takes a describe.
			d, err := t.eks.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
				ClusterName: aws.String(cluster), AssociationId: a.AssociationId})
			if err != nil {
				return nil, err
			}
			if d.Association == nil {
				continue
			}
			out = append(out, eksPodIdentity{
				Namespace:      aws.ToString(d.Association.Namespace),
				ServiceAccount: aws.ToString(d.Association.ServiceAccount),
				RoleArn:        aws.ToString(d.Association.RoleArn),
			})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func (t *sdkTransport) accessEntries(ctx context.Context, cluster string) ([]eksAccessEntry, error) {
	var out []eksAccessEntry
	var next *string
	for {
		page, err := t.eks.ListAccessEntries(ctx, &eks.ListAccessEntriesInput{ClusterName: aws.String(cluster), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, principal := range page.AccessEntries {
			e := eksAccessEntry{PrincipalArn: principal}
			var pnext *string
			for {
				pol, err := t.eks.ListAssociatedAccessPolicies(ctx, &eks.ListAssociatedAccessPoliciesInput{
					ClusterName: aws.String(cluster), PrincipalArn: aws.String(principal), NextToken: pnext})
				if err != nil {
					return nil, err
				}
				for _, p := range pol.AssociatedAccessPolicies {
					ap := eksAccessPolicy{PolicyArn: aws.ToString(p.PolicyArn)}
					if p.AccessScope != nil {
						ap.AccessScope.Type = string(p.AccessScope.Type)
					}
					e.AccessPolicies = append(e.AccessPolicies, ap)
				}
				if pol.NextToken == nil {
					break
				}
				pnext = pol.NextToken
			}
			out = append(out, e)
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}
