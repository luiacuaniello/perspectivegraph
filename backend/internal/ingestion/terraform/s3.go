package terraform

// S3, in the shape of a Cloud Custodian export, which is how the engine reads buckets: per
// bucket its tags, its policy, its Block Public Access settings and its ACL, and the
// account's own Block Public Access settings when the configuration sets them.

type custodianBundle struct {
	AccountID string          `json:"account_id,omitempty"`
	Policies  []custodianPart `json:"policies"`
}

type custodianPart struct {
	Policy    string           `json:"policy"`
	Resource  string           `json:"resource"`
	Resources []map[string]any `json:"resources"`
}

var blockKeys = map[string]string{
	"block_public_acls":       "BlockPublicAcls",
	"ignore_public_acls":      "IgnorePublicAcls",
	"block_public_policy":     "BlockPublicPolicy",
	"restrict_public_buckets": "RestrictPublicBuckets",
}

func (p *Plan) s3(v View) (custodianBundle, []string) {
	b := custodianBundle{AccountID: p.Account}
	var notes []string
	buckets := map[string]map[string]any{}
	var order []string
	bucket := func(name string) map[string]any {
		if r, ok := buckets[name]; ok {
			return r
		}
		r := map[string]any{"Name": name}
		buckets[name] = r
		order = append(order, name)
		return r
	}
	for _, r := range p.Resources(v, "aws_s3_bucket") {
		if !r.Managed() {
			continue
		}
		res := bucket(p.nameOf(v, r))
		if tags, ok := r.Values["tags"].(map[string]any); ok {
			res["Tags"] = tagList(tags)
		}
		// The bucket's own policy attribute, from the provider versions that wrote it
		// there; aws_s3_bucket_policy below wins when both are set.
		if cfg := p.configOf(r); cfg != nil {
			if _, configured := cfg.Expressions["policy"]; configured {
				if s := p.Str(v, r, "policy"); s != "" {
					res["Policy"] = s
				} else if !p.Known(v, r, "policy") {
					notes = append(notes, r.Address+": its policy is known only after apply")
				}
			}
		}
	}
	for _, r := range p.Resources(v, "aws_s3_bucket_policy") {
		if !r.Managed() {
			continue
		}
		name := p.Str(v, r, "bucket")
		if name == "" {
			notes = append(notes, r.Address+": the bucket it applies to is known only after apply")
			continue
		}
		res := bucket(name)
		if s := p.Str(v, r, "policy"); s != "" && p.Known(v, r, "policy") {
			res["Policy"] = s
			continue
		}
		notes = append(notes, r.Address+": the policy of bucket "+name+" is known only after apply")
	}
	for _, r := range p.Resources(v, "aws_s3_bucket_public_access_block") {
		if !r.Managed() {
			continue
		}
		name := p.Str(v, r, "bucket")
		if name == "" {
			continue
		}
		res := bucket(name)
		cfg := map[string]any{}
		for tf, aws := range blockKeys {
			on, _ := r.Values[tf].(bool)
			cfg[aws] = on
		}
		res["c7n:PublicAccessBlock"] = cfg
	}
	for _, r := range p.Resources(v, "aws_s3_bucket_acl") {
		if !r.Managed() {
			continue
		}
		name := p.Str(v, r, "bucket")
		if name == "" {
			continue
		}
		var grants []any
		switch p.Str(v, r, "acl") {
		case "public-read":
			grants = append(grants, grant("READ"))
		case "public-read-write":
			grants = append(grants, grant("READ"), grant("WRITE"))
		}
		if len(grants) > 0 {
			bucket(name)["Acl"] = map[string]any{"Grants": grants}
		}
	}
	part := custodianPart{Policy: "terraform-plan", Resource: "aws.s3", Resources: []map[string]any{}}
	for _, name := range order {
		part.Resources = append(part.Resources, buckets[name])
	}
	b.Policies = append(b.Policies, part)

	for _, r := range p.Resources(v, "aws_s3_account_public_access_block") {
		if !r.Managed() {
			continue
		}
		cfg := map[string]any{}
		for tf, aws := range blockKeys {
			on, _ := r.Values[tf].(bool)
			cfg[aws] = on
		}
		acct := p.Str(v, r, "account_id")
		if acct == "" {
			acct = p.Account
		}
		b.Policies = append(b.Policies, custodianPart{Policy: "terraform-plan-account", Resource: "aws.account",
			Resources: []map[string]any{{"account_id": acct, "c7n:s3-public-block": cfg}}})
	}
	return b, notes
}

func grant(permission string) map[string]any {
	return map[string]any{
		"Grantee":    map[string]any{"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
		"Permission": permission,
	}
}
