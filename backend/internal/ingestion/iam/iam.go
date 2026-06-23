// Package iam turns an AWS account's IAM reality into a privilege-escalation
// graph - the "BloodHound for cloud" question scanners never answer: not "which
// policy is too broad" but "who can become admin, and from where". It consumes
// the output of `aws iam get-account-authorization-details` (the whole account's
// users, roles, groups and policies in one document), flattens each principal's
// effective Allow'd actions, and emits:
//
//	Role trust "Principal":"*"   → the role is internet_exposed (publicly assumable)
//	known privesc primitive      → principal ──CAN_ESCALATE_TO──▶ account-admin (crown jewel)
//	already-admin (Allow *:*)    → principal ──CAN_ESCALATE_TO──▶ account-admin
//	trust grants assume to a peer→ peer ──ASSUMES──▶ role   (role chaining)
//
// The synthetic "account-admin" node is the crown jewel: full account control.
// Combined with the network/topology collectors, a complete path emerges -
// internet ─▶ instance ─▶ assumes role ─▶ CAN_ESCALATE_TO ─▶ account compromise.
//
// Honest simplifications (documented, not hidden): Resource scoping, Condition
// keys, explicit Deny and NotAction are ignored, so an Allow is treated as
// account-wide. Detection therefore over-reports rather than misses - the same
// trade PMapper makes when it drops resource awareness for speed.
package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "iam" }

// ── typed view of get-account-authorization-details ─────────────────

type authDetails struct {
	UserDetailList []struct {
		UserName                string         `json:"UserName"`
		Arn                     string         `json:"Arn"`
		GroupList               []string       `json:"GroupList"`
		AttachedManagedPolicies []attachedRef  `json:"AttachedManagedPolicies"`
		UserPolicyList          []inlinePolicy `json:"UserPolicyList"`
	} `json:"UserDetailList"`
	GroupDetailList []struct {
		GroupName               string         `json:"GroupName"`
		Arn                     string         `json:"Arn"`
		AttachedManagedPolicies []attachedRef  `json:"AttachedManagedPolicies"`
		GroupPolicyList         []inlinePolicy `json:"GroupPolicyList"`
	} `json:"GroupDetailList"`
	RoleDetailList []struct {
		RoleName                 string         `json:"RoleName"`
		Arn                      string         `json:"Arn"`
		AssumeRolePolicyDocument policyDoc      `json:"AssumeRolePolicyDocument"`
		AttachedManagedPolicies  []attachedRef  `json:"AttachedManagedPolicies"`
		RolePolicyList           []inlinePolicy `json:"RolePolicyList"`
		Tags                     []awsTag       `json:"Tags"`
	} `json:"RoleDetailList"`
	Policies []struct {
		PolicyName        string `json:"PolicyName"`
		Arn               string `json:"Arn"`
		DefaultVersionID  string `json:"DefaultVersionId"`
		PolicyVersionList []struct {
			Document         policyDoc `json:"Document"`
			VersionID        string    `json:"VersionId"`
			IsDefaultVersion bool      `json:"IsDefaultVersion"`
		} `json:"PolicyVersionList"`
	} `json:"Policies"`
}

type attachedRef struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type inlinePolicy struct {
	PolicyName     string    `json:"PolicyName"`
	PolicyDocument policyDoc `json:"PolicyDocument"`
}

type awsTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// policyDoc is an IAM policy document. The IAM API returns it URL-encoded as a
// string; the CLI returns it as a decoded JSON object - we accept both.
type policyDoc struct {
	Statement []statement `json:"Statement"`
}

func (d *policyDoc) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var encoded string
		if err := json.Unmarshal(b, &encoded); err != nil {
			return err
		}
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			return fmt.Errorf("url-decode policy document: %w", err)
		}
		b = []byte(decoded)
	}
	type alias policyDoc // avoid recursing into this UnmarshalJSON
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*d = policyDoc(a)
	return nil
}

type statement struct {
	Effect    string         `json:"Effect"`
	Action    stringOrSlice  `json:"Action"`
	Principal trustPrincipal `json:"Principal"`
}

// stringOrSlice decodes a JSON field that IAM expresses as either a single
// string or an array of strings (Action, Resource, Principal.AWS …).
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '[' {
		var many []string
		if err := json.Unmarshal(b, &many); err != nil {
			return err
		}
		*s = many
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

// trustPrincipal models the "Principal" of a role trust statement: the literal
// "*" (anyone), or an object with AWS/Service/Federated members.
type trustPrincipal struct {
	All     bool
	AWS     stringOrSlice
	Service stringOrSlice
}

func (p *trustPrincipal) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		p.All = s == "*"
		if s != "*" && s != "" {
			p.AWS = stringOrSlice{s}
		}
		return nil
	}
	var obj struct {
		AWS     stringOrSlice `json:"AWS"`
		Service stringOrSlice `json:"Service"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	p.AWS, p.Service = obj.AWS, obj.Service
	for _, a := range obj.AWS {
		if a == "*" {
			p.All = true
		}
	}
	return nil
}

// ── parse ───────────────────────────────────────────────────────────

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var d authDetails
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode get-account-authorization-details: %w", err)
	}

	// Index every managed policy's default-version document by ARN.
	managed := map[string]policyDoc{}
	for _, p := range d.Policies {
		var doc policyDoc
		found := false
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion || v.VersionID == p.DefaultVersionID {
				doc, found = v.Document, true
				break
			}
		}
		if !found && len(p.PolicyVersionList) > 0 {
			doc = p.PolicyVersionList[0].Document
		}
		managed[p.Arn] = doc
	}

	// Group → its policy documents, so users inherit their groups' permissions.
	groupDocs := map[string][]policyDoc{}
	for _, gr := range d.GroupDetailList {
		var docs []policyDoc
		for _, ip := range gr.GroupPolicyList {
			docs = append(docs, ip.PolicyDocument)
		}
		for _, am := range gr.AttachedManagedPolicies {
			if doc, ok := managed[am.PolicyArn]; ok {
				docs = append(docs, doc)
			}
		}
		groupDocs[gr.GroupName] = docs
	}

	g := &builder{nodes: map[string]ontology.Node{}}
	arnToID := map[string]string{} // principal ARN → graph node id

	// The crown jewel: admin-equivalent control of the account. Every principal
	// that is, or can become, admin gets an edge to it.
	adminID := g.stub(ontology.LabelIAMRole, "perspectivegraph:account-admin")
	g.upsert(ontology.Node{ID: adminID, Label: ontology.LabelIAMRole, Name: "account-admin (effective)",
		Properties: map[string]any{ontology.PropCrownJewel: true, "admin": true,
			"synthetic": true, "note": "full account control - IAM escalation target"}})

	// Users.
	for _, u := range d.UserDetailList {
		if u.UserName == "" {
			continue
		}
		id := ontology.NewID(ontology.LabelUser, u.Arn)
		arnToID[u.Arn] = id
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelUser, Name: u.UserName,
			Properties: map[string]any{ontology.PropARN: u.Arn}})

		var docs []policyDoc
		for _, ip := range u.UserPolicyList {
			docs = append(docs, ip.PolicyDocument)
		}
		for _, am := range u.AttachedManagedPolicies {
			if doc, ok := managed[am.PolicyArn]; ok {
				docs = append(docs, doc)
			}
		}
		for _, grp := range u.GroupList {
			docs = append(docs, groupDocs[grp]...)
		}
		g.escalation(id, allowedActions(docs), adminID)
	}

	// Roles.
	for _, ro := range d.RoleDetailList {
		if ro.RoleName == "" {
			continue
		}
		id := ontology.NewID(ontology.LabelIAMRole, ro.Arn)
		arnToID[ro.Arn] = id
		props := map[string]any{ontology.PropARN: ro.Arn}
		tags := map[string]string{}
		for _, t := range ro.Tags {
			tags[t.Key] = t.Value
		}
		if ingestion.CrownJewelFromTags(tags) {
			props[ontology.PropCrownJewel] = true
		}
		// A role anyone can assume is, in effect, internet-reachable.
		if trustsEveryone(ro.AssumeRolePolicyDocument) {
			props[ontology.PropInternetExposed] = true
			props["public_trust"] = true
		}
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelIAMRole, Name: ro.RoleName, Properties: props})

		var docs []policyDoc
		for _, ip := range ro.RolePolicyList {
			docs = append(docs, ip.PolicyDocument)
		}
		for _, am := range ro.AttachedManagedPolicies {
			if doc, ok := managed[am.PolicyArn]; ok {
				docs = append(docs, doc)
			}
		}
		g.escalation(id, allowedActions(docs), adminID)
	}

	// Second pass: role chaining - a principal the trust policy names can assume
	// the role. Resolved now that every principal node id is known.
	for _, ro := range d.RoleDetailList {
		roleID, ok := arnToID[ro.Arn]
		if !ok {
			continue
		}
		for _, st := range ro.AssumeRolePolicyDocument.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			for _, peerArn := range st.Principal.AWS {
				if peerID, ok := arnToID[peerArn]; ok && peerID != roleID {
					g.edge(ontology.EdgeAssumes, peerID, roleID, 0.8)
				}
			}
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      g.nodeSlice(),
		Edges:      g.edges,
	}}, nil
}

// allowedActions flattens every Allow'd action across a principal's documents.
func allowedActions(docs []policyDoc) actionSet {
	var a actionSet
	for _, d := range docs {
		for _, st := range d.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			for _, act := range st.Action {
				a = a.add(act)
			}
		}
	}
	return a
}

// trustsEveryone reports whether any Allow statement lets "*" assume the role.
func trustsEveryone(doc policyDoc) bool {
	for _, st := range doc.Statement {
		if strings.EqualFold(st.Effect, "Allow") && st.Principal.All {
			return true
		}
	}
	return false
}

// ── builder + helpers ───────────────────────────────────────────────

type builder struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
}

// escalation draws the principal's edge to account-admin, if any: a direct edge
// when it is already admin, or one labelled with the matched privesc primitives.
func (b *builder) escalation(principalID string, actions actionSet, adminID string) {
	if principalID == adminID {
		return
	}
	if actions.IsAdmin() {
		b.edgeWith(ontology.EdgeCanEscalateTo, principalID, adminID, 0.99,
			map[string]any{"reason": "already administrator-equivalent (Allow *:*)"})
		return
	}
	if prims := detectPrivesc(actions); len(prims) > 0 {
		b.edgeWith(ontology.EdgeCanEscalateTo, principalID, adminID, 0.9,
			map[string]any{"primitives": strings.Join(prims, "; "), "primitive_count": len(prims)})
	}
}

func (b *builder) upsert(n ontology.Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		for k, v := range n.Properties {
			if existing.Properties == nil {
				existing.Properties = map[string]any{}
			}
			existing.Properties[k] = v
		}
		if n.Name != "" {
			existing.Name = n.Name
		}
		b.nodes[n.ID] = existing
		return
	}
	b.nodes[n.ID] = n
}

func (b *builder) stub(label ontology.Label, name string) string {
	id := ontology.NewID(label, name)
	if _, ok := b.nodes[id]; !ok {
		b.nodes[id] = ontology.Node{ID: id, Label: label, Name: name}
	}
	return id
}

func (b *builder) edge(t ontology.EdgeType, from, to string, p float64) {
	b.edges = append(b.edges, ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p})
}

func (b *builder) edgeWith(t ontology.EdgeType, from, to string, p float64, props map[string]any) {
	b.edges = append(b.edges, ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p, Properties: props})
}

func (b *builder) nodeSlice() []ontology.Node {
	out := make([]ontology.Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		out = append(out, n)
	}
	return out
}
