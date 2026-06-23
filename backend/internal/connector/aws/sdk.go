package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ec2API and iamAPI are the narrow slices of aws-sdk-go-v2 the transport needs.
// Narrowing the surface keeps the mapping unit-testable with a fake client — no
// real AWS account required to prove the SDK output → collector JSON conversion.
type ec2API interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error)
}

type iamAPI interface {
	GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
}

// sdkTransport pulls live AWS state and renders it as the exact describe-* JSON
// the cloudnet/iam collectors already parse, so the live path and the fixtures
// path converge on identical downstream code.
type sdkTransport struct {
	ec2 ec2API
	iam iamAPI
}

// newSDK builds the live AWS transport. It uses the standard credential chain
// (env / shared profile / IRSA / instance role); when RoleARN is set it assumes
// that role first — the "customer grants you a read-only cross-account role"
// agentless model. Credentials are resolved lazily on first call, so a wrong
// role surfaces as a connector error in GET /connectors rather than blocking boot.
func newSDK(ctx context.Context, cfg Config) (transport, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if cfg.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.RoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return &sdkTransport{
		ec2: ec2.NewFromConfig(awsCfg),
		iam: iam.NewFromConfig(awsCfg),
	}, nil
}

func (*sdkTransport) Mode() string { return "sdk" }

func (t *sdkTransport) Fetch(ctx context.Context, feed Feed) ([]byte, error) {
	switch feed {
	case FeedNetwork:
		return t.fetchNetwork(ctx)
	case FeedIAM:
		return t.fetchIAM(ctx)
	default:
		return nil, nil
	}
}

// ── network feed (EC2 → cloudnet bundle) ─────────────────────────────

func (t *sdkTransport) fetchNetwork(ctx context.Context) ([]byte, error) {
	b := networkBundle{Provider: "aws"}

	var sgTok *string
	for {
		out, err := t.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: sgTok})
		if err != nil {
			return nil, fmt.Errorf("describe security groups: %w", err)
		}
		for _, sg := range out.SecurityGroups {
			g := sgJSON{GroupID: aws.ToString(sg.GroupId), GroupName: aws.ToString(sg.GroupName)}
			for _, perm := range sg.IpPermissions {
				p := permJSON{}
				for _, r := range perm.IpRanges {
					p.IPRanges = append(p.IPRanges, ipRangeJSON{CidrIp: aws.ToString(r.CidrIp)})
				}
				for _, u := range perm.UserIdGroupPairs {
					p.UserIDGroupPairs = append(p.UserIDGroupPairs, sgRefJSON{GroupID: aws.ToString(u.GroupId)})
				}
				g.IPPermissions = append(g.IPPermissions, p)
			}
			b.SecurityGroups = append(b.SecurityGroups, g)
		}
		if out.NextToken == nil {
			break
		}
		sgTok = out.NextToken
	}

	var instTok *string
	for {
		out, err := t.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: instTok})
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range out.Reservations {
			for _, inst := range res.Instances {
				i := instJSON{InstanceID: aws.ToString(inst.InstanceId)}
				for _, sg := range inst.SecurityGroups {
					i.SecurityGroups = append(i.SecurityGroups, sgRefJSON{GroupID: aws.ToString(sg.GroupId)})
				}
				for _, tag := range inst.Tags {
					i.Tags = append(i.Tags, tagJSON{Key: aws.ToString(tag.Key), Value: aws.ToString(tag.Value)})
				}
				b.Instances = append(b.Instances, i)
			}
		}
		if out.NextToken == nil {
			break
		}
		instTok = out.NextToken
	}

	var pcxTok *string
	for {
		out, err := t.ec2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{NextToken: pcxTok})
		if err != nil {
			return nil, fmt.Errorf("describe vpc peering connections: %w", err)
		}
		for _, pcx := range out.VpcPeeringConnections {
			var v peeringJSON
			if pcx.RequesterVpcInfo != nil {
				v.RequesterVpcInfo.VpcID = aws.ToString(pcx.RequesterVpcInfo.VpcId)
			}
			if pcx.AccepterVpcInfo != nil {
				v.AccepterVpcInfo.VpcID = aws.ToString(pcx.AccepterVpcInfo.VpcId)
			}
			b.VPCPeerings = append(b.VPCPeerings, v)
		}
		if out.NextToken == nil {
			break
		}
		pcxTok = out.NextToken
	}

	return json.Marshal(b)
}

type networkBundle struct {
	Provider       string        `json:"provider"`
	SecurityGroups []sgJSON      `json:"security_groups"`
	Instances      []instJSON    `json:"instances"`
	VPCPeerings    []peeringJSON `json:"vpc_peerings"`
}

type sgJSON struct {
	GroupID       string     `json:"GroupId"`
	GroupName     string     `json:"GroupName"`
	IPPermissions []permJSON `json:"IpPermissions"`
}

type permJSON struct {
	IPRanges         []ipRangeJSON `json:"IpRanges"`
	UserIDGroupPairs []sgRefJSON   `json:"UserIdGroupPairs"`
}

type ipRangeJSON struct {
	CidrIp string `json:"CidrIp"`
}

type sgRefJSON struct {
	GroupID string `json:"GroupId"`
}

type instJSON struct {
	InstanceID     string      `json:"InstanceId"`
	SecurityGroups []sgRefJSON `json:"SecurityGroups"`
	Tags           []tagJSON   `json:"Tags"`
}

type tagJSON struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type peeringJSON struct {
	RequesterVpcInfo vpcInfoJSON `json:"RequesterVpcInfo"`
	AccepterVpcInfo  vpcInfoJSON `json:"AccepterVpcInfo"`
}

type vpcInfoJSON struct {
	VpcID string `json:"VpcId"`
}

// ── IAM feed (get-account-authorization-details) ─────────────────────

func (t *sdkTransport) fetchIAM(ctx context.Context) ([]byte, error) {
	var b iamBundle
	var marker *string
	for {
		out, err := t.iam.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("get account authorization details: %w", err)
		}
		for _, u := range out.UserDetailList {
			b.UserDetailList = append(b.UserDetailList, iamUser{
				UserName:                aws.ToString(u.UserName),
				Arn:                     aws.ToString(u.Arn),
				GroupList:               u.GroupList,
				AttachedManagedPolicies: mapAttached(u.AttachedManagedPolicies),
				UserPolicyList:          mapInline(u.UserPolicyList),
			})
		}
		for _, g := range out.GroupDetailList {
			b.GroupDetailList = append(b.GroupDetailList, iamGroup{
				GroupName:               aws.ToString(g.GroupName),
				Arn:                     aws.ToString(g.Arn),
				AttachedManagedPolicies: mapAttached(g.AttachedManagedPolicies),
				GroupPolicyList:         mapInline(g.GroupPolicyList),
			})
		}
		for _, r := range out.RoleDetailList {
			b.RoleDetailList = append(b.RoleDetailList, iamRole{
				RoleName:                 aws.ToString(r.RoleName),
				Arn:                      aws.ToString(r.Arn),
				AssumeRolePolicyDocument: aws.ToString(r.AssumeRolePolicyDocument),
				AttachedManagedPolicies:  mapAttached(r.AttachedManagedPolicies),
				RolePolicyList:           mapInline(r.RolePolicyList),
				Tags:                     mapTags(r.Tags),
			})
		}
		for _, p := range out.Policies {
			pol := iamPolicy{
				PolicyName:       aws.ToString(p.PolicyName),
				Arn:              aws.ToString(p.Arn),
				DefaultVersionID: aws.ToString(p.DefaultVersionId),
			}
			for _, v := range p.PolicyVersionList {
				pol.PolicyVersionList = append(pol.PolicyVersionList, iamPolicyVersion{
					Document:         aws.ToString(v.Document),
					VersionID:        aws.ToString(v.VersionId),
					IsDefaultVersion: v.IsDefaultVersion,
				})
			}
			b.Policies = append(b.Policies, pol)
		}
		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}
	return json.Marshal(b)
}

type iamBundle struct {
	UserDetailList  []iamUser   `json:"UserDetailList"`
	GroupDetailList []iamGroup  `json:"GroupDetailList"`
	RoleDetailList  []iamRole   `json:"RoleDetailList"`
	Policies        []iamPolicy `json:"Policies"`
}

type iamUser struct {
	UserName                string        `json:"UserName"`
	Arn                     string        `json:"Arn"`
	GroupList               []string      `json:"GroupList,omitempty"`
	AttachedManagedPolicies []iamAttached `json:"AttachedManagedPolicies,omitempty"`
	UserPolicyList          []iamInline   `json:"UserPolicyList,omitempty"`
}

type iamGroup struct {
	GroupName               string        `json:"GroupName"`
	Arn                     string        `json:"Arn"`
	AttachedManagedPolicies []iamAttached `json:"AttachedManagedPolicies,omitempty"`
	GroupPolicyList         []iamInline   `json:"GroupPolicyList,omitempty"`
}

type iamRole struct {
	RoleName                 string        `json:"RoleName"`
	Arn                      string        `json:"Arn"`
	AssumeRolePolicyDocument string        `json:"AssumeRolePolicyDocument,omitempty"` // URL-encoded; the iam parser unescapes
	AttachedManagedPolicies  []iamAttached `json:"AttachedManagedPolicies,omitempty"`
	RolePolicyList           []iamInline   `json:"RolePolicyList,omitempty"`
	Tags                     []iamTag      `json:"Tags,omitempty"`
}

type iamPolicy struct {
	PolicyName        string             `json:"PolicyName"`
	Arn               string             `json:"Arn"`
	DefaultVersionID  string             `json:"DefaultVersionId"`
	PolicyVersionList []iamPolicyVersion `json:"PolicyVersionList,omitempty"`
}

type iamPolicyVersion struct {
	Document         string `json:"Document,omitempty"` // URL-encoded
	VersionID        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
}

type iamAttached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type iamInline struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument string `json:"PolicyDocument,omitempty"` // URL-encoded
}

type iamTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func mapAttached(in []iamtypes.AttachedPolicy) []iamAttached {
	var out []iamAttached
	for _, a := range in {
		out = append(out, iamAttached{PolicyName: aws.ToString(a.PolicyName), PolicyArn: aws.ToString(a.PolicyArn)})
	}
	return out
}

func mapInline(in []iamtypes.PolicyDetail) []iamInline {
	var out []iamInline
	for _, p := range in {
		out = append(out, iamInline{PolicyName: aws.ToString(p.PolicyName), PolicyDocument: aws.ToString(p.PolicyDocument)})
	}
	return out
}

func mapTags(in []iamtypes.Tag) []iamTag {
	var out []iamTag
	for _, tg := range in {
		out = append(out, iamTag{Key: aws.ToString(tg.Key), Value: aws.ToString(tg.Value)})
	}
	return out
}
