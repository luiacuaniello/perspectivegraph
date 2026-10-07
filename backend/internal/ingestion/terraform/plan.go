package terraform

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The plan as `terraform show -json` writes it - the documented machine-readable format
// (https://developer.hashicorp.com/terraform/internals/json-format), read as far as this
// package needs it. Everything else in the document is ignored.
type planJSON struct {
	FormatVersion   string           `json:"format_version"`
	PlannedValues   *valuesRoot      `json:"planned_values"`
	PriorState      *stateJSON       `json:"prior_state"`
	ResourceChanges []resourceChange `json:"resource_changes"`
	Configuration   *configRoot      `json:"configuration"`
	Timestamp       string           `json:"timestamp"`
}

type stateJSON struct {
	Values *valuesRoot `json:"values"`
}

type valuesRoot struct {
	RootModule valuesModule `json:"root_module"`
}

type valuesModule struct {
	Address      string           `json:"address"`
	Resources    []valuesResource `json:"resources"`
	ChildModules []valuesModule   `json:"child_modules"`
}

type valuesResource struct {
	Address      string         `json:"address"`
	Mode         string         `json:"mode"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	Index        any            `json:"index"`
	ProviderName string         `json:"provider_name"`
	Values       map[string]any `json:"values"`
}

type resourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Index         any    `json:"index"`
	Change        struct {
		Actions      []string       `json:"actions"`
		AfterUnknown map[string]any `json:"after_unknown"`
	} `json:"change"`
}

type configRoot struct {
	ProviderConfig map[string]struct {
		Name        string                     `json:"name"`
		Expressions map[string]json.RawMessage `json:"expressions"`
	} `json:"provider_config"`
	RootModule configModule `json:"root_module"`
}

type configModule struct {
	Resources   []configResource      `json:"resources"`
	ModuleCalls map[string]moduleCall `json:"module_calls"`
	Outputs     map[string]struct {
		Expression json.RawMessage `json:"expression"`
	} `json:"outputs"`
}

type configResource struct {
	Address     string                     `json:"address"`
	Mode        string                     `json:"mode"`
	Type        string                     `json:"type"`
	Name        string                     `json:"name"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

type moduleCall struct {
	Expressions map[string]json.RawMessage `json:"expressions"`
	Module      configModule               `json:"module"`
}

// expression is one attribute's expression in the configuration: a constant, or the
// references it is built from. A nested block is a list of maps of expressions instead.
type expression struct {
	References    []string `json:"references"`
	ConstantValue any      `json:"constant_value"`
}

// View is which state of the configuration's resources is read: as they are before the
// plan is applied, or as the plan leaves them.
type View int

const (
	// Prior is the state the plan starts from: what is deployed now.
	Prior View = iota
	// Planned is the state the plan would leave.
	Planned
)

// Resource is one resource instance of the plan, in one view.
type Resource struct {
	// Address is the instance's full address, module path and index included:
	// module.app.aws_instance.this["a"].
	Address string
	// Module is the module instance it lives in ("" for the root), keys included:
	// module.app["eu"].
	Module string
	Mode   string // managed | data
	Type   string
	Name   string
	Index  any
	// Values are the attributes known in this view. An attribute known only after apply
	// is absent here and present in Unknown.
	Values  map[string]any
	Unknown map[string]any
	// Actions are what the plan does to it (planned view): create, update, delete,
	// no-op, read.
	Actions []string
}

// Managed reports whether the configuration manages it, as opposed to reading it.
func (r *Resource) Managed() bool { return r.Mode == "managed" }

// Changed reports whether the plan changes it.
func (r *Resource) Changed() bool {
	for _, a := range r.Actions {
		if a != "no-op" && a != "read" {
			return true
		}
	}
	return false
}

// Plan is a parsed plan, with the configuration it came from.
type Plan struct {
	Timestamp time.Time
	// Account and Region are what the plan's resources say about where they live, unless
	// the caller said so first (see Read).
	Account, Region string

	views   map[View][]*Resource
	byAddr  map[View]map[string]*Resource
	config  map[string]*configModule // by module path without instance keys
	calls   map[string]*moduleCall   // the call that instantiates a module path
	actions map[string][]string
}

// Read parses a plan. account and region, when given, win over what the plan suggests.
func Read(r io.Reader, account, region string) (*Plan, error) {
	var raw planJSON
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode terraform plan: %w", err)
	}
	if raw.PlannedValues == nil && raw.ResourceChanges == nil {
		return nil, fmt.Errorf("not a terraform plan: no planned_values or resource_changes (expected the output of `terraform show -json <planfile>`)")
	}
	p := &Plan{
		views:   map[View][]*Resource{},
		byAddr:  map[View]map[string]*Resource{Prior: {}, Planned: {}},
		config:  map[string]*configModule{},
		calls:   map[string]*moduleCall{},
		actions: map[string][]string{},
	}
	if t, err := time.Parse(time.RFC3339, raw.Timestamp); err == nil {
		p.Timestamp = t.UTC()
	}
	unknown := map[string]map[string]any{}
	for _, rc := range raw.ResourceChanges {
		p.actions[rc.Address] = rc.Change.Actions
		unknown[rc.Address] = rc.Change.AfterUnknown
	}
	// Data sources are read while planning and land in the prior state only; both views
	// see them, since nothing the plan does changes what they read.
	var data []*Resource
	if raw.PriorState != nil && raw.PriorState.Values != nil {
		walkValues(&raw.PriorState.Values.RootModule, func(m string, vr valuesResource) {
			res := newResource(m, vr)
			if res.Mode == "data" {
				data = append(data, res)
				return
			}
			p.add(Prior, res)
		})
	}
	if raw.PlannedValues != nil {
		walkValues(&raw.PlannedValues.RootModule, func(m string, vr valuesResource) {
			res := newResource(m, vr)
			if res.Mode == "data" {
				return
			}
			res.Unknown = unknown[res.Address]
			res.Actions = p.actions[res.Address]
			p.add(Planned, res)
		})
	}
	for _, d := range data {
		p.add(Prior, d)
		cp := *d
		p.add(Planned, &cp)
	}
	if raw.Configuration != nil {
		p.indexConfig("", &raw.Configuration.RootModule)
		if pc, ok := raw.Configuration.ProviderConfig["aws"]; ok {
			if e, ok := pc.Expressions["region"]; ok {
				var x expression
				if json.Unmarshal(e, &x) == nil {
					p.Region, _ = x.ConstantValue.(string)
				}
			}
		}
	}
	p.Account = account
	if p.Account == "" {
		p.Account = p.inferAccount()
	}
	if region != "" {
		p.Region = region
	}
	if p.Region == "" {
		p.Region = p.inferRegion()
	}
	return p, nil
}

func newResource(module string, vr valuesResource) *Resource {
	values := vr.Values
	if values == nil {
		values = map[string]any{}
	}
	return &Resource{Address: vr.Address, Module: module, Mode: vr.Mode, Type: vr.Type, Name: vr.Name, Index: vr.Index, Values: values}
}

func (p *Plan) add(v View, r *Resource) {
	p.views[v] = append(p.views[v], r)
	p.byAddr[v][r.Address] = r
}

// walkValues visits every resource of a module tree with the module instance it lives in.
func walkValues(m *valuesModule, fn func(module string, r valuesResource)) {
	for _, r := range m.Resources {
		fn(m.Address, r)
	}
	for i := range m.ChildModules {
		walkValues(&m.ChildModules[i], fn)
	}
}

func (p *Plan) indexConfig(path string, m *configModule) {
	p.config[path] = m
	for name, call := range m.ModuleCalls {
		child := "module." + name
		if path != "" {
			child = path + "." + child
		}
		c := call
		p.calls[child] = &c
		p.indexConfig(child, &c.Module)
	}
}

// Resources returns the view's resources of the given types, in address order.
func (p *Plan) Resources(v View, types ...string) []*Resource {
	want := map[string]bool{}
	for _, t := range types {
		want[t] = true
	}
	var out []*Resource
	for _, r := range p.views[v] {
		if len(want) == 0 || want[r.Type] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// Changed reports whether the plan changes anything at all.
func (p *Plan) Changed() bool {
	for _, a := range p.actions {
		for _, x := range a {
			if x != "no-op" && x != "read" {
				return true
			}
		}
	}
	return false
}

// keyless strips the instance keys from a module path: module.app["eu"] -> module.app,
// the way the configuration names it.
var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

func keyless(path string) string { return instanceKey.ReplaceAllString(path, "") }

// configOf is the configuration block a resource instance was declared by.
func (p *Plan) configOf(r *Resource) *configResource {
	m := p.config[keyless(r.Module)]
	if m == nil {
		return nil
	}
	want := r.Type + "." + r.Name
	if r.Mode == "data" {
		want = "data." + want
	}
	for i := range m.Resources {
		if m.Resources[i].Address == want {
			return &m.Resources[i]
		}
	}
	return nil
}

// Attr returns an attribute of a resource in a view: the value when it is known, or, when
// it is known only after apply, what the configuration says it will be built from -
// another resource's identifier, or a placeholder standing for it. The path walks nested
// blocks: Attr(r, "route", 0, "gateway_id").
//
// The second result is false when nothing can be said: the attribute is unknown and its
// expression cannot be followed (a local value, a function of something unknown).
func (p *Plan) Attr(v View, r *Resource, path ...any) (any, bool) {
	return p.attr(v, r, 0, path...)
}

// maxDepth bounds how far references are followed. Terraform's own references form no
// cycle, but the plan is input: one written by hand can make two attributes refer to each
// other, and following them without a bound would never end.
const maxDepth = 32

func (p *Plan) attr(v View, r *Resource, depth int, path ...any) (any, bool) {
	if len(path) == 0 || depth > maxDepth {
		return nil, false
	}
	known, _ := dig(r.Values, path...)
	if !unknownAt(r.Unknown, path...) {
		return known, known != nil
	}
	// Known only after apply. Its expression's references say what it is built from,
	// which is what it will be only when the expression is a bare reference - an
	// identifier passed along. A document is built by a function of its references, and
	// stays unknown.
	name, _ := path[len(path)-1].(string)
	if !identifierAttr[name] {
		return nil, false
	}
	cfg := p.configOf(r)
	if cfg == nil {
		return nil, false
	}
	refs, ok := exprRefs(cfg.Expressions, path...)
	if !ok {
		return nil, false
	}
	// A list partly known - one group named by its id, one created by the same plan -
	// keeps the elements it has, and the references fill in the rest.
	var vals []any
	if l, ok := known.([]any); ok {
		for _, e := range l {
			if e != nil {
				vals = append(vals, e)
			}
		}
	}
	for _, x := range p.resolve(v, r.Module, fitting(refs, name), depth) {
		if !containsValue(vals, x) {
			vals = append(vals, x)
		}
	}
	switch len(vals) {
	case 0:
		return nil, false
	case 1:
		if isList(r.Values, path...) {
			return []any{vals[0]}, true
		}
		return vals[0], true
	default:
		return vals, true
	}
}

// identifierAttr are the attributes that hold another resource's identifier, name or ARN:
// written in a configuration as a bare reference to it, so that what they will be is
// what that resource's attribute will be.
var identifierAttr = map[string]bool{
	"id": true, "arn": true, "name": true, "bucket": true, "function_name": true, "role": true, "user": true,
	"subnet_id": true, "vpc_id": true, "vpc_security_group_ids": true, "security_groups": true,
	"security_group_id": true, "source_security_group_id": true, "referenced_security_group_id": true,
	"route_table_id": true, "gateway_id": true, "nat_gateway_id": true, "transit_gateway_id": true,
	"vpc_peering_connection_id": true, "egress_only_gateway_id": true, "network_interface_id": true,
	"instance": true, "instance_id": true, "roles": true, "users": true, "allocation_id": true, "iam_instance_profile": true,
	"policy_arn": true, "permissions_boundary": true, "managed_policy_arns": true,
	"default_route_table_id": true, "main_route_table_id": true, "default_security_group_id": true, "default_network_acl_id": true,
}

// attrTypes are the resource types an identifier attribute can point at. A reference to
// another type - an argument of a function the attribute is computed with, or another
// route's target in a block written as one expression - is not what it holds.
var attrTypes = map[string][]string{
	"gateway_id":                   {"aws_internet_gateway", "aws_vpn_gateway"},
	"nat_gateway_id":               {"aws_nat_gateway"},
	"transit_gateway_id":           {"aws_ec2_transit_gateway"},
	"vpc_peering_connection_id":    {"aws_vpc_peering_connection"},
	"egress_only_gateway_id":       {"aws_egress_only_internet_gateway"},
	"subnet_id":                    {"aws_subnet", "aws_default_subnet"},
	"route_table_id":               {"aws_route_table", "aws_default_route_table", "aws_vpc"},
	"default_route_table_id":       {"aws_vpc"},
	"vpc_id":                       {"aws_vpc", "aws_default_vpc"},
	"instance":                     {"aws_instance"},
	"instance_id":                  {"aws_instance"},
	"security_groups":              {"aws_security_group", "aws_default_security_group", "aws_vpc"},
	"vpc_security_group_ids":       {"aws_security_group", "aws_default_security_group", "aws_vpc"},
	"security_group_id":            {"aws_security_group", "aws_default_security_group", "aws_vpc"},
	"source_security_group_id":     {"aws_security_group", "aws_default_security_group", "aws_vpc"},
	"referenced_security_group_id": {"aws_security_group", "aws_default_security_group", "aws_vpc"},
	"iam_instance_profile":         {"aws_iam_instance_profile"},
	"role":                         {"aws_iam_role"},
	"roles":                        {"aws_iam_role"},
	"users":                        {"aws_iam_user"},
	"user":                         {"aws_iam_user"},
	"bucket":                       {"aws_s3_bucket"},
	"function_name":                {"aws_lambda_function"},
}

// fitting keeps the references that can be what attr holds: those to a resource of a
// type it points at, and those through a variable or a module output, whose type cannot
// be told here.
func fitting(refs []string, attr string) []string {
	types, ok := attrTypes[attr]
	if !ok {
		return refs
	}
	var out []string
	for _, r := range refs {
		steps := refStep.FindAllString(r, -1)
		if len(steps) == 0 {
			continue
		}
		typ := steps[0]
		if typ == "data" && len(steps) > 1 {
			typ = steps[1]
		}
		if typ == "var" || typ == "module" {
			out = append(out, r)
			continue
		}
		for _, t := range types {
			if typ == t {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// Str is Attr for a single string.
func (p *Plan) Str(v View, r *Resource, path ...any) string {
	x, _ := p.Attr(v, r, path...)
	switch t := x.(type) {
	case string:
		return t
	case []any:
		if len(t) == 1 {
			s, _ := t[0].(string)
			return s
		}
	}
	return ""
}

// Strs is Attr for a list of strings (a single string counts as a list of one).
func (p *Plan) Strs(v View, r *Resource, path ...any) []string {
	x, _ := p.Attr(v, r, path...)
	var out []string
	switch t := x.(type) {
	case string:
		if t != "" {
			out = append(out, t)
		}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// Known reports whether an attribute is settled in this view: known now, or known to be
// built from something the plan can name.
func (p *Plan) Known(v View, r *Resource, path ...any) bool {
	_, ok := p.Attr(v, r, path...)
	if ok {
		return true
	}
	return !unknownAt(r.Unknown, path...)
}

// resolve follows references, written relative to a module instance, to the values they
// stand for.
func (p *Plan) resolve(v View, module string, refs []string, depth int) []any {
	var out []any
	seen := map[string]bool{}
	for _, ref := range mostSpecific(refs) {
		for _, val := range p.resolveOne(v, module, ref, depth+1) {
			key := fmt.Sprint(val)
			if !seen[key] {
				seen[key] = true
				out = append(out, val)
			}
		}
	}
	return out
}

// mostSpecific drops a reference another one in the list extends: Terraform lists both
// aws_subnet.a.id and aws_subnet.a for one use.
func mostSpecific(refs []string) []string {
	var out []string
	for _, r := range refs {
		extended := false
		for _, o := range refs {
			if o != r && (strings.HasPrefix(o, r+".") || strings.HasPrefix(o, r+"[")) {
				extended = true
				break
			}
		}
		if !extended {
			out = append(out, r)
		}
	}
	return out
}

// refPart splits a reference into its traversal steps: aws_instance.web[0].id ->
// aws_instance, web, [0], id.
var refStep = regexp.MustCompile(`[^.\[\]]+|\[[^\]]*\]`)

func (p *Plan) resolveOne(v View, module, ref string, depth int) []any {
	if depth > maxDepth {
		return nil
	}
	steps := refStep.FindAllString(ref, -1)
	if len(steps) == 0 {
		return nil
	}
	switch steps[0] {
	case "var":
		if len(steps) < 2 || module == "" {
			return nil
		}
		call := p.calls[keyless(module)]
		if call == nil {
			return nil
		}
		refs, ok := exprRefs(call.Expressions, steps[1])
		if !ok {
			return nil
		}
		var out []any
		for _, r := range mostSpecific(refs) {
			out = append(out, p.resolveOne(v, parentModule(module), r, depth+1)...)
		}
		return out
	case "module":
		if len(steps) < 3 {
			return nil
		}
		childBase := "module." + steps[1]
		if module != "" {
			childBase = module + "." + childBase
		}
		rest := steps[2:]
		key := ""
		if strings.HasPrefix(rest[0], "[") {
			key, rest = rest[0], rest[1:]
		}
		if len(rest) == 0 {
			return nil
		}
		m := p.config[keyless(childBase)]
		if m == nil {
			return nil
		}
		out, ok := m.Outputs[rest[0]]
		if !ok {
			return nil
		}
		refs, ok := exprRefs(map[string]json.RawMessage{"x": out.Expression}, "x")
		if !ok {
			return nil
		}
		var vals []any
		for _, inst := range p.moduleInstances(v, childBase, key) {
			for _, r := range mostSpecific(refs) {
				vals = append(vals, p.resolveOne(v, inst, r, depth+1)...)
			}
		}
		return vals
	case "local", "each", "count", "path", "self", "terraform":
		return nil
	}
	mode, typ, name := "managed", steps[0], ""
	rest := steps[1:]
	if typ == "data" {
		if len(steps) < 3 {
			return nil
		}
		mode, typ, rest = "data", steps[1], steps[2:]
	}
	if len(rest) == 0 {
		return nil
	}
	name, rest = rest[0], rest[1:]
	key := ""
	if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
		key, rest = rest[0], rest[1:]
	}
	attr := "id"
	if len(rest) > 0 {
		attr = rest[0]
	}
	var out []any
	for _, r := range p.views[v] {
		if r.Mode != mode || r.Type != typ || r.Name != name || r.Module != module {
			continue
		}
		if key != "" && indexKey(r.Index) != key {
			continue
		}
		if val, ok := p.attr(v, r, depth+1, attr); ok {
			out = append(out, val)
			continue
		}
		if ph := p.placeholder(v, r, attr); ph != "" {
			out = append(out, ph)
		}
	}
	return flatten(out)
}

// moduleInstances lists the instances of a module path present in the view: module.app,
// or module.app[0] and module.app[1] when it is counted.
func (p *Plan) moduleInstances(v View, base, key string) []string {
	if key != "" {
		return []string{base + key}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range p.views[v] {
		if r.Module == base || (strings.HasPrefix(r.Module, base+"[") && keyless(r.Module) == keyless(base)) {
			if !seen[r.Module] {
				seen[r.Module] = true
				out = append(out, r.Module)
			}
		}
	}
	if len(out) == 0 {
		out = []string{base}
	}
	sort.Strings(out)
	return out
}

func parentModule(module string) string {
	i := strings.LastIndex(module, ".module.")
	if i < 0 {
		return ""
	}
	return module[:i]
}

func indexKey(idx any) string {
	switch t := idx.(type) {
	case nil:
		return ""
	case float64:
		return "[" + strconv.Itoa(int(t)) + "]"
	case string:
		return "[" + strconv.Quote(t) + "]"
	}
	return fmt.Sprintf("[%v]", idx)
}

func flatten(vals []any) []any {
	var out []any
	for _, v := range vals {
		if l, ok := v.([]any); ok {
			out = append(out, flatten(l)...)
			continue
		}
		out = append(out, v)
	}
	return out
}

// exprRefs finds the references of the expression at a path through nested blocks.
func exprRefs(exprs map[string]json.RawMessage, path ...any) ([]string, bool) {
	if len(path) == 0 {
		return nil, false
	}
	name, ok := path[0].(string)
	if !ok {
		return nil, false
	}
	raw, ok := exprs[name]
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		var e expression
		if err := json.Unmarshal(raw, &e); err != nil || len(e.References) == 0 {
			return nil, false
		}
		return e.References, true
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		// A block written as an attribute - route = [ ... ] - has one expression for all
		// of it: its references are what every nested attribute can be built from, and
		// fitting picks, for each, the ones of the right type.
		var e expression
		if json.Unmarshal(raw, &e) != nil || len(e.References) == 0 {
			return nil, false
		}
		return e.References, true
	}
	i, ok := path[1].(int)
	if !ok || i < 0 || i >= len(blocks) {
		return nil, false
	}
	return exprRefs(blocks[i], path[2:]...)
}

// dig reads a value at a path of map keys and list indexes.
func dig(v any, path ...any) (any, bool) {
	cur := v
	for _, step := range path {
		switch s := step.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			if cur, ok = m[s]; !ok {
				return nil, false
			}
		case int:
			l, ok := cur.([]any)
			if !ok || s < 0 || s >= len(l) {
				return nil, false
			}
			cur = l[s]
		default:
			return nil, false
		}
	}
	return cur, true
}

// unknownAt reports whether after_unknown marks the value at a path - the whole of it,
// something above it, or any part of it - as known only after apply.
func unknownAt(unknown map[string]any, path ...any) bool {
	var cur any = unknown
	for _, step := range path {
		if b, ok := cur.(bool); ok {
			return b
		}
		next, ok := dig(cur, step)
		if !ok {
			return false
		}
		cur = next
	}
	return anyTrue(cur)
}

func anyTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case []any:
		for _, e := range t {
			if anyTrue(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if anyTrue(e) {
				return true
			}
		}
	}
	return false
}

func containsValue(l []any, x any) bool {
	for _, e := range l {
		if fmt.Sprint(e) == fmt.Sprint(x) {
			return true
		}
	}
	return false
}

func isList(values map[string]any, path ...any) bool {
	v, ok := dig(values, path...)
	if !ok {
		return false
	}
	_, isL := v.([]any)
	return isL
}

var accountInARN = regexp.MustCompile(`arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):`)
var regionInARN = regexp.MustCompile(`arn:aws[a-z-]*:[a-z0-9-]+:([a-z]{2}(?:-[a-z]+)+-\d):`)

// inferAccount takes the account most of the plan's ARNs name, or the one a
// aws_caller_identity data source read. A plan whose resources are all new names none,
// and the caller has to say.
func (p *Plan) inferAccount() string {
	for _, r := range p.views[Prior] {
		if r.Mode == "data" && r.Type == "aws_caller_identity" {
			if a, _ := r.Values["account_id"].(string); a != "" {
				return a
			}
		}
	}
	return mostCommon(p, accountInARN)
}

func (p *Plan) inferRegion() string {
	for _, v := range []View{Planned, Prior} {
		for _, r := range p.views[v] {
			if s, _ := r.Values["region"].(string); s != "" {
				return s
			}
		}
	}
	return mostCommon(p, regionInARN)
}

func mostCommon(p *Plan, re *regexp.Regexp) string {
	counts := map[string]int{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range re.FindAllStringSubmatch(t, -1) {
				counts[m[1]]++
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, v := range []View{Prior, Planned} {
		for _, r := range p.views[v] {
			walk(r.Values)
		}
	}
	best, n := "", 0
	for k, c := range counts {
		if c > n || (c == n && k < best) {
			best, n = k, c
		}
	}
	return best
}
