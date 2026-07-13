package api

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/graphql-go/graphql"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
)

// The frozen public GraphQL contract. See docs/API-STABILITY.md.
const schemaGolden = "../../../docs/api/schema.graphql"

// TestGraphQLSchemaSnapshot freezes the public GraphQL API. It renders the live schema
// to canonical SDL and compares it to the committed golden; any drift fails the test, so
// a change to the public contract is a deliberate, reviewable act. After an intended
// change, regenerate the golden and review the diff:
//
//	UPDATE_SCHEMA=1 go test ./internal/api -run TestGraphQLSchemaSnapshot
//
// A change that removes or renames a field (or narrows a type) is BREAKING and needs a
// major version bump - see docs/API-STABILITY.md.
func TestGraphQLSchemaSnapshot(t *testing.T) {
	ctx := context.Background()
	m, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	schema, err := New(m, analyzer.NewService(m, time.Second, nil), nil).Schema()
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	got := renderSDL(schema)

	if os.Getenv("UPDATE_SCHEMA") == "1" {
		if err := os.WriteFile(schemaGolden, []byte(got), 0o644); err != nil { // #nosec G306 -- public contract, not a secret
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", schemaGolden, len(got))
		return
	}
	want, err := os.ReadFile(schemaGolden)
	if err != nil {
		t.Fatalf("read golden (create it with UPDATE_SCHEMA=1): %v", err)
	}
	if got != string(want) {
		t.Errorf("GraphQL schema drifted from the frozen contract %s.\n"+
			"If the change is intended, regenerate with UPDATE_SCHEMA=1 and review the diff; a\n"+
			"removed/renamed field or a narrowed type is BREAKING and needs a major bump\n"+
			"(see docs/API-STABILITY.md).", schemaGolden)
	}
}

// renderSDL renders a graphql-go schema as deterministic SDL: types and fields sorted by
// name so the golden is stable and diffs read cleanly. Introspection types (__*) and the
// built-in scalars are omitted.
func renderSDL(s graphql.Schema) string {
	tm := s.TypeMap()
	names := make([]string, 0, len(tm))
	for name := range tm {
		if strings.HasPrefix(name, "__") || isBuiltinScalar(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		switch t := tm[name].(type) {
		case *graphql.Object:
			writeBlock(&b, "type", name, fieldLines(t.Fields()))
		case *graphql.InputObject:
			writeBlock(&b, "input", name, inputLines(t.Fields()))
		case *graphql.Enum:
			writeBlock(&b, "enum", name, enumLines(t.Values()))
		case *graphql.Scalar:
			fmt.Fprintf(&b, "scalar %s\n\n", name)
		}
	}
	return b.String()
}

func writeBlock(b *strings.Builder, kind, name string, lines []string) {
	fmt.Fprintf(b, "%s %s {\n", kind, name)
	for _, l := range lines {
		fmt.Fprintf(b, "  %s\n", l)
	}
	b.WriteString("}\n\n")
}

func fieldLines(fields graphql.FieldDefinitionMap) []string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		f := fields[k]
		args := ""
		if len(f.Args) > 0 {
			as := make([]string, 0, len(f.Args))
			for _, a := range f.Args {
				as = append(as, fmt.Sprintf("%s: %s", a.PrivateName, a.Type.String()))
			}
			sort.Strings(as)
			args = "(" + strings.Join(as, ", ") + ")"
		}
		dep := ""
		if f.DeprecationReason != "" {
			dep = " @deprecated"
		}
		out = append(out, fmt.Sprintf("%s%s: %s%s", f.Name, args, f.Type.String(), dep))
	}
	return out
}

func inputLines(fields graphql.InputObjectFieldMap) []string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s: %s", fields[k].PrivateName, fields[k].Type.String()))
	}
	return out
}

func enumLines(values []*graphql.EnumValueDefinition) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.Name)
	}
	sort.Strings(out)
	return out
}

func isBuiltinScalar(name string) bool {
	switch name {
	case "String", "Int", "Float", "Boolean", "ID":
		return true
	}
	return false
}
