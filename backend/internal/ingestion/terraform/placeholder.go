package terraform

import "strings"

// A resource the plan creates has no identifier yet: AWS hands it out on apply. It still
// needs one in the graph, and other resources point at it - an instance at its security
// group, a policy at its role - so it gets a placeholder, the same wherever it is named.
//
// A placeholder keeps the prefix of the identifier AWS will assign (sg-, igw-, i-), because
// readers decide by it: a route to igw-… is a route to an internet gateway. Its body is
// the resource's address, which says, to whoever reads the graph, which block of the
// configuration it stands for.
const plannedMark = "planned:"

// idPrefix is the prefix of the identifier AWS gives each type, for the types whose
// identifier is an opaque id rather than a name or an ARN.
var idPrefix = map[string]string{
	"aws_vpc":                          "vpc-",
	"aws_subnet":                       "subnet-",
	"aws_internet_gateway":             "igw-",
	"aws_egress_only_internet_gateway": "eigw-",
	"aws_nat_gateway":                  "nat-",
	"aws_route_table":                  "rtb-",
	"aws_security_group":               "sg-",
	"aws_network_acl":                  "acl-",
	"aws_instance":                     "i-",
	"aws_eip":                          "eipalloc-",
	"aws_network_interface":            "eni-",
	"aws_vpc_peering_connection":       "pcx-",
	"aws_ec2_transit_gateway":          "tgw-",
	"aws_default_vpc":                  "vpc-",
	"aws_default_subnet":               "subnet-",
	"aws_default_route_table":          "rtb-",
	"aws_default_security_group":       "sg-",
	"aws_default_network_acl":          "acl-",
}

// IsPlaceholder reports whether an identifier stands for a resource not created yet.
func IsPlaceholder(id string) bool { return strings.Contains(id, plannedMark) }

// placeholder is what an attribute of a resource will be once AWS assigns it, as far as it
// can be said now: the deterministic ones (an IAM role's ARN, a bucket's name) built the
// way AWS builds them, the rest a stand-in. Empty when there is nothing to stand for.
func (p *Plan) placeholder(v View, r *Resource, attr string) string {
	switch attr {
	case "arn":
		return p.arnOf(v, r)
	case "id":
		switch r.Type {
		case "aws_iam_role", "aws_iam_user", "aws_iam_group", "aws_iam_instance_profile":
			return p.nameOf(v, r)
		case "aws_iam_policy":
			return p.arnOf(v, r)
		case "aws_s3_bucket":
			return p.nameOf(v, r)
		case "aws_lambda_function":
			return p.nameOf(v, r)
		}
		if pre, ok := idPrefix[r.Type]; ok {
			return pre + plannedMark + r.Address
		}
		return plannedMark + r.Address
	case "name", "bucket", "function_name":
		return p.nameOf(v, r)
	case "default_security_group_id":
		return "sg-" + plannedMark + r.Address + ".default"
	case "default_route_table_id", "main_route_table_id":
		return "rtb-" + plannedMark + r.Address + ".main"
	case "default_network_acl_id":
		return "acl-" + plannedMark + r.Address + ".default"
	}
	return ""
}

// nameOf is a resource's name: the one configured, or a stand-in when it is generated
// (name_prefix) and so known only after apply.
func (p *Plan) nameOf(v View, r *Resource) string {
	for _, k := range []string{"name", "bucket", "function_name"} {
		if s, _ := r.Values[k].(string); s != "" {
			return s
		}
	}
	return plannedMark + r.Address
}

// arnOf is a resource's ARN, built the way AWS builds it for the types where it is
// determined by name, account and Region. The account, when no ARN in the plan names it
// and the caller did not, is a stand-in too.
func (p *Plan) arnOf(v View, r *Resource) string {
	if s, _ := r.Values["arn"].(string); s != "" {
		return s
	}
	account := p.Account
	if account == "" {
		account = "planned"
	}
	region := p.Region
	if s, _ := r.Values["region"].(string); s != "" {
		region = s
	}
	path, _ := r.Values["path"].(string)
	if path == "" {
		path = "/"
	}
	name := p.nameOf(v, r)
	switch r.Type {
	case "aws_iam_role":
		return "arn:aws:iam::" + account + ":role" + path + name
	case "aws_iam_user":
		return "arn:aws:iam::" + account + ":user" + path + name
	case "aws_iam_group":
		return "arn:aws:iam::" + account + ":group" + path + name
	case "aws_iam_policy":
		return "arn:aws:iam::" + account + ":policy" + path + name
	case "aws_iam_instance_profile":
		return "arn:aws:iam::" + account + ":instance-profile" + path + name
	case "aws_lambda_function":
		return "arn:aws:lambda:" + region + ":" + account + ":function:" + name
	case "aws_s3_bucket":
		return "arn:aws:s3:::" + name
	}
	return ""
}
