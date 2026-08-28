package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ec2API and iamAPI are the narrow slices of aws-sdk-go-v2 the transport needs.
// Narrowing the surface keeps the mapping unit-testable with a fake client - no
// real AWS account required to prove the SDK output → collector JSON conversion.
type ec2API interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error)
	// The network layer that turns "SG open to 0.0.0.0/0" into "actually reachable":
	// route tables (is there an internet-gateway route?), NACLs (does the subnet admit
	// it?) and subnets (which route table / NACL each instance sits behind).
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
}

type iamAPI interface {
	GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	// ListInstanceProfiles resolves an instance's IAM instance profile to the role it
	// carries - the link that joins the network half of the graph to the identity half.
	// EC2 reports only the *profile* ARN; the role behind it lives in IAM.
	ListInstanceProfiles(context.Context, *iam.ListInstanceProfilesInput, ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error)
	// GetPolicy and GetPolicyVersion fetch a permissions-boundary policy document the
	// authorization-details bundle referenced by ARN but did not include. Without the
	// document the boundary can be seen but not intersected, and the escalation
	// detector has to fall back to over-reporting - which is the false positive the
	// boundary lab demonstrates. Both are read-only and inside the same SecurityAudit
	// grant the connector already asks for.
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// sdkTransport pulls live AWS state and renders it as the exact describe-* JSON
// the cloudnet/iam collectors already parse, so the live path and the fixtures
// path converge on identical downstream code.
type sdkTransport struct {
	ec2 ec2API
	iam iamAPI
	sts stsAPI

	// account memoises GetCallerIdentity. It cannot change for a given transport -
	// the credentials are fixed at construction - so asking once per process is
	// enough, and asking once per pass would be a needless call on every cycle.
	accountOnce sync.Once
	account     string
}

// stsAPI is the one call needed to learn which account the credentials speak for.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// newSDK builds the live AWS transport. It uses the standard credential chain
// (env / shared profile / IRSA / instance role); when RoleARN is set it assumes
// that role first - the "customer grants you a read-only cross-account role"
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
		sts: sts.NewFromConfig(awsCfg),
	}, nil
}

func (*sdkTransport) Mode() string { return "sdk" }

// Account asks AWS which account these credentials belong to, rather than making the
// operator type an id that has to agree with the role they configured. Getting that
// pair out of step would be silent and expensive: assets would be filed under an
// account they are not in.
//
// A failure is logged and returns "" - the pass then produces the unqualified ids it
// always did, which is wrong only in the sense of being less specific. Refusing to
// collect because one extra call failed would trade a whole account's visibility for
// a label.
func (t *sdkTransport) Account(ctx context.Context) string {
	t.accountOnce.Do(func() {
		if t.sts == nil {
			return // no STS client: collect unqualified rather than crash the pass
		}
		out, err := t.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			slog.Warn("aws connector: could not determine the account id; assets will be collected unqualified",
				"err", err)
			return
		}
		t.account = aws.ToString(out.Account)
	})
	return t.account
}

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
				// Real accounts keep terminated/shutting-down instances in DescribeInstances
				// for a while; they have no live network presence, so skip them rather than
				// emit phantom nodes (and phantom internet-exposed seeds).
				if st := inst.State; st != nil && (st.Name == ec2types.InstanceStateNameTerminated || st.Name == ec2types.InstanceStateNameShuttingDown) {
					continue
				}
				i := instJSON{InstanceID: aws.ToString(inst.InstanceId), SubnetID: aws.ToString(inst.SubnetId)}
				// The instance profile is what an attacker with a foothold on the box turns
				// into IAM credentials (via IMDS) - the hop that connects "internet reached
				// this instance" to "and now it is an identity".
				if p := inst.IamInstanceProfile; p != nil {
					i.IamInstanceProfile = &profileRefJSON{Arn: aws.ToString(p.Arn)}
				}
				// IMDSv2 enforcement decides how cheap that hop is: with HttpTokens=optional
				// a blind SSRF reads the credentials outright; required means the attacker
				// needs code execution to mint a token first.
				if m := inst.MetadataOptions; m != nil {
					i.MetadataOptions = &metadataOptsJSON{HTTPTokens: string(m.HttpTokens)}
				}
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

	// Route tables: emit each table's routes, and index which route table each subnet
	// uses (an explicit association wins; a subnet with none uses its VPC's main table).
	subnetRT, mainRTByVPC := map[string]string{}, map[string]string{}
	var rtTok *string
	for {
		out, err := t.ec2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{NextToken: rtTok})
		if err != nil {
			return nil, fmt.Errorf("describe route tables: %w", err)
		}
		for _, rt := range out.RouteTables {
			rtID := aws.ToString(rt.RouteTableId)
			r := routeTableJSON{RouteTableID: rtID}
			for _, rte := range rt.Routes {
				// Capture every default-route target kind: a real 0.0.0.0/0 route may point
				// at a NAT/transit-gateway/peering/egress-only-IGW - none of which are the
				// internet gateway - so the collector can tell "private egress" from
				// "internet-exposed" instead of seeing a blank gateway.
				r.Routes = append(r.Routes, routeJSON{
					DestinationCidrBlock: aws.ToString(rte.DestinationCidrBlock),
					GatewayID:            aws.ToString(rte.GatewayId),
					NatGatewayID:         aws.ToString(rte.NatGatewayId),
					TransitGatewayID:     aws.ToString(rte.TransitGatewayId),
					VpcPeeringConnID:     aws.ToString(rte.VpcPeeringConnectionId),
					EgressOnlyIGWID:      aws.ToString(rte.EgressOnlyInternetGatewayId),
				})
			}
			b.RouteTables = append(b.RouteTables, r)
			for _, a := range rt.Associations {
				if aws.ToBool(a.Main) {
					mainRTByVPC[aws.ToString(rt.VpcId)] = rtID
				} else if sid := aws.ToString(a.SubnetId); sid != "" {
					subnetRT[sid] = rtID
				}
			}
		}
		if out.NextToken == nil {
			break
		}
		rtTok = out.NextToken
	}

	// Network ACLs: emit each ACL's entries and index each subnet's ACL.
	subnetNacl := map[string]string{}
	var aclTok *string
	for {
		out, err := t.ec2.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{NextToken: aclTok})
		if err != nil {
			return nil, fmt.Errorf("describe network acls: %w", err)
		}
		for _, acl := range out.NetworkAcls {
			aclID := aws.ToString(acl.NetworkAclId)
			n := naclJSON{NetworkACLID: aclID}
			for _, e := range acl.Entries {
				n.Entries = append(n.Entries, naclEntryJSON{
					RuleNumber: int(aws.ToInt32(e.RuleNumber)),
					Egress:     aws.ToBool(e.Egress),
					CidrBlock:  aws.ToString(e.CidrBlock),
					RuleAction: string(e.RuleAction),
				})
			}
			b.NetworkACLs = append(b.NetworkACLs, n)
			for _, a := range acl.Associations {
				if sid := aws.ToString(a.SubnetId); sid != "" {
					subnetNacl[sid] = aclID
				}
			}
		}
		if out.NextToken == nil {
			break
		}
		aclTok = out.NextToken
	}

	// Subnets: resolve each to its route table (explicit or the VPC main) + NACL, the
	// shape the collector uses to gate SG-open exposure on real reachability.
	var subTok *string
	for {
		out, err := t.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{NextToken: subTok})
		if err != nil {
			return nil, fmt.Errorf("describe subnets: %w", err)
		}
		for _, s := range out.Subnets {
			sid := aws.ToString(s.SubnetId)
			rt := subnetRT[sid]
			if rt == "" {
				rt = mainRTByVPC[aws.ToString(s.VpcId)]
			}
			b.Subnets = append(b.Subnets, subnetJSON{SubnetID: sid, RouteTableID: rt, NetworkACLID: subnetNacl[sid]})
		}
		if out.NextToken == nil {
			break
		}
		subTok = out.NextToken
	}

	// Instance profiles: EC2 hands out only the *profile* ARN, so resolve each to the
	// role it carries. This is what lets the collector draw instance --ASSUMES--> role,
	// joining the network graph to the identity graph. Deliberately NON-fatal: if the
	// grant lacks iam:ListInstanceProfiles we emit no profile map (and therefore no
	// ASSUMES edges) rather than sinking the whole network feed over one permission.
	var ipTok *string
	for {
		out, err := t.iam.ListInstanceProfiles(ctx, &iam.ListInstanceProfilesInput{Marker: ipTok})
		if err != nil {
			b.InstanceProfiles = nil
			break
		}
		for _, p := range out.InstanceProfiles {
			ip := instanceProfileJSON{Arn: aws.ToString(p.Arn)}
			for _, r := range p.Roles {
				ip.Roles = append(ip.Roles, profileRoleJSON{Arn: aws.ToString(r.Arn), RoleName: aws.ToString(r.RoleName)})
			}
			b.InstanceProfiles = append(b.InstanceProfiles, ip)
		}
		if !out.IsTruncated {
			break
		}
		ipTok = out.Marker
	}

	return json.Marshal(b)
}

type networkBundle struct {
	Provider         string                `json:"provider"`
	SecurityGroups   []sgJSON              `json:"security_groups"`
	Instances        []instJSON            `json:"instances"`
	VPCPeerings      []peeringJSON         `json:"vpc_peerings"`
	Subnets          []subnetJSON          `json:"subnets,omitempty"`
	RouteTables      []routeTableJSON      `json:"route_tables,omitempty"`
	NetworkACLs      []naclJSON            `json:"network_acls,omitempty"`
	InstanceProfiles []instanceProfileJSON `json:"instance_profiles,omitempty"`
}

// instanceProfileJSON mirrors iam list-instance-profiles: a profile and the role(s) it
// carries, so an instance's profile ARN can be resolved to the role an attacker inherits.
type instanceProfileJSON struct {
	Arn   string            `json:"Arn"`
	Roles []profileRoleJSON `json:"Roles"`
}

type profileRoleJSON struct {
	Arn      string `json:"Arn"`
	RoleName string `json:"RoleName"`
}

// profileRefJSON is the IamInstanceProfile block ec2 describe-instances returns: the
// *profile* ARN (not the role's).
type profileRefJSON struct {
	Arn string `json:"Arn"`
}

// metadataOptsJSON carries the IMDS posture: HttpTokens "required" (IMDSv2 enforced) or
// "optional" (IMDSv1 still answers).
type metadataOptsJSON struct {
	HTTPTokens string `json:"HttpTokens"`
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
	InstanceID         string            `json:"InstanceId"`
	SubnetID           string            `json:"SubnetId,omitempty"`
	SecurityGroups     []sgRefJSON       `json:"SecurityGroups"`
	Tags               []tagJSON         `json:"Tags"`
	IamInstanceProfile *profileRefJSON   `json:"IamInstanceProfile,omitempty"`
	MetadataOptions    *metadataOptsJSON `json:"MetadataOptions,omitempty"`
}

type subnetJSON struct {
	SubnetID     string `json:"SubnetId"`
	RouteTableID string `json:"RouteTableId,omitempty"`
	NetworkACLID string `json:"NetworkAclId,omitempty"`
}

type routeTableJSON struct {
	RouteTableID string      `json:"RouteTableId"`
	Routes       []routeJSON `json:"Routes"`
}

type routeJSON struct {
	DestinationCidrBlock string `json:"DestinationCidrBlock"`
	GatewayID            string `json:"GatewayId,omitempty"`
	NatGatewayID         string `json:"NatGatewayId,omitempty"`
	TransitGatewayID     string `json:"TransitGatewayId,omitempty"`
	VpcPeeringConnID     string `json:"VpcPeeringConnectionId,omitempty"`
	EgressOnlyIGWID      string `json:"EgressOnlyInternetGatewayId,omitempty"`
}

type naclJSON struct {
	NetworkACLID string          `json:"NetworkAclId"`
	Entries      []naclEntryJSON `json:"Entries"`
}

type naclEntryJSON struct {
	RuleNumber int    `json:"RuleNumber"`
	Egress     bool   `json:"Egress"`
	CidrBlock  string `json:"CidrBlock,omitempty"`
	RuleAction string `json:"RuleAction"`
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
				PermissionsBoundary:     mapBoundary(u.PermissionsBoundary),
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
				PermissionsBoundary:      mapBoundary(r.PermissionsBoundary),
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
	t.resolveBoundaryPolicies(ctx, &b)
	return json.Marshal(b)
}

// resolveBoundaryPolicies fills in permissions-boundary documents the
// authorization-details bundle referenced by ARN but did not carry.
//
// A boundary policy that is set as a boundary and attached to nothing else need not
// appear in the bundle's Policies list, and a boundary whose document we cannot read
// can be seen but not intersected - leaving the evaluator to over-report exactly the
// escalation the boundary blocks. Two read-only calls per missing boundary close
// that, and only for boundaries actually in use.
//
// Failures are deliberately not fatal: one unreadable policy must not sink the whole
// IAM feed. The ingestion side already handles a boundary it cannot resolve honestly
// - it keeps the escalation but marks and scores it as unverified - so degrading to
// that is strictly better than dropping every principal in the account.
func (t *sdkTransport) resolveBoundaryPolicies(ctx context.Context, b *iamBundle) {
	have := make(map[string]bool, len(b.Policies))
	for _, p := range b.Policies {
		have[p.Arn] = true
	}
	missing := map[string]bool{}
	note := func(pb *iamBoundary) {
		if pb != nil && pb.PermissionsBoundaryArn != "" && !have[pb.PermissionsBoundaryArn] {
			missing[pb.PermissionsBoundaryArn] = true
		}
	}
	for _, u := range b.UserDetailList {
		note(u.PermissionsBoundary)
	}
	for _, r := range b.RoleDetailList {
		note(r.PermissionsBoundary)
	}
	if len(missing) == 0 {
		return
	}
	// Sorted so the emitted bundle is deterministic - the fixtures path and the live
	// path have to converge on identical downstream code, byte order included.
	arns := make([]string, 0, len(missing))
	for arn := range missing {
		arns = append(arns, arn)
	}
	sort.Strings(arns)

	for _, arn := range arns {
		pol, err := t.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
		if err != nil || pol.Policy == nil || pol.Policy.DefaultVersionId == nil {
			continue
		}
		ver, err := t.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: pol.Policy.DefaultVersionId,
		})
		if err != nil || ver.PolicyVersion == nil {
			continue
		}
		b.Policies = append(b.Policies, iamPolicy{
			PolicyName:       aws.ToString(pol.Policy.PolicyName),
			Arn:              arn,
			DefaultVersionID: aws.ToString(pol.Policy.DefaultVersionId),
			PolicyVersionList: []iamPolicyVersion{{
				Document:         aws.ToString(ver.PolicyVersion.Document),
				VersionID:        aws.ToString(ver.PolicyVersion.VersionId),
				IsDefaultVersion: true,
			}},
		})
	}
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
	PermissionsBoundary     *iamBoundary  `json:"PermissionsBoundary,omitempty"` // caps effective permissions to the intersection
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
	PermissionsBoundary      *iamBoundary  `json:"PermissionsBoundary,omitempty"` // caps effective permissions to the intersection
}

// iamBoundary is the permissions boundary GetAccountAuthorizationDetails reports on a
// user or role. It names a managed policy by ARN; the document itself travels in the
// bundle's Policies list (see resolveBoundaryPolicies). Dropping this field is what
// made the engine call a bounded and an unbounded principal equally dangerous.
type iamBoundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType,omitempty"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn,omitempty"`
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

func mapBoundary(in *iamtypes.AttachedPermissionsBoundary) *iamBoundary {
	if in == nil || aws.ToString(in.PermissionsBoundaryArn) == "" {
		return nil
	}
	return &iamBoundary{
		PermissionsBoundaryType: string(in.PermissionsBoundaryType),
		PermissionsBoundaryArn:  aws.ToString(in.PermissionsBoundaryArn),
	}
}

func mapTags(in []iamtypes.Tag) []iamTag {
	var out []iamTag
	for _, tg := range in {
		out = append(out, iamTag{Key: aws.ToString(tg.Key), Value: aws.ToString(tg.Value)})
	}
	return out
}
