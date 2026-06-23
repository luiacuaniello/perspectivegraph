// Package age implements graph.Store on top of PostgreSQL + Apache AGE.
//
// AGE exposes openCypher via the ag_catalog.cypher() set-returning function.
// Each session must LOAD 'age' and put ag_catalog on the search_path, so every
// operation runs inside a short transaction that performs that setup first.
//
// Injection model. AGE cannot bind labels/edge-types as parameters and its
// agtype value binding is awkward, so values are inlined into the Cypher text.
// Three layers keep that safe:
//
//   - the Cypher body is wrapped in a *randomized* dollar-quote tag ($pg<rand>$)
//     that a value cannot contain, so a value can never break out to the SQL
//     layer (the previous fixed $perspective$ tag was forgeable);
//   - string values are single-quoted and escaped by cypherQuote, so they can't
//     break out of the Cypher string literal;
//   - labels and edge types are validated against the ontology allowlist, and
//     the graph name against a strict identifier pattern, before interpolation.
package age

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// maxOpenConns sizes the per-store connection pool. AGE session state (LOAD +
// search_path) is re-established at the start of every transaction (see withAGE),
// so any pooled connection is safe to use - there is no need to pin to one.
const maxOpenConns = 8

// graphNameRe is the strict identifier pattern a graph name must match before it
// is interpolated into SQL. Tenant-derived names already pass through
// graph.NormalizeTenant; this is the fail-closed boundary check.
var graphNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Store struct {
	db    *sql.DB
	graph string

	// indexed memoizes which label tables already have an id index this process,
	// so the (idempotent) CREATE INDEX runs at most once per label.
	indexed sync.Map
}

func newStore(dsn, graphName string) (*Store, error) {
	if !graphNameRe.MatchString(graphName) {
		return nil, fmt.Errorf("invalid graph name %q", graphName)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	return &Store{db: db, graph: graphName}, nil
}

// Open connects to Postgres and verifies the AGE extension + target graph are
// available.
func Open(ctx context.Context, dsn, graphName string) (*Store, error) {
	s, err := newStore(dsn, graphName)
	if err != nil {
		return nil, err
	}
	if err := s.Ping(ctx); err != nil {
		s.db.Close()
		return nil, err
	}
	return s, nil
}

// OpenOrCreate is like Open but creates the target graph if it does not exist
// yet - used to spin up a tenant's isolated graph on first reference.
func OpenOrCreate(ctx context.Context, dsn, graphName string) (*Store, error) {
	s, err := newStore(dsn, graphName)
	if err != nil {
		return nil, err
	}
	if err := s.ensureGraph(ctx); err != nil {
		s.db.Close()
		return nil, err
	}
	return s, nil
}

// ensureGraph creates the AGE graph if it is not already present.
func (s *Store) ensureGraph(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		// Graph name is identifier-validated; safe to interpolate.
		_, err := tx.ExecContext(ctx, fmt.Sprintf(
			`SELECT create_graph('%s') WHERE NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = '%s')`,
			s.graph, s.graph))
		return err
	})
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	// Confirm AGE is installed and the graph exists.
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		q, err := s.cypherSQL(`RETURN 1`, `v agtype`)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, q)
		return err
	})
}

// UpsertNode creates or updates a vertex with NATIVE agtype properties (so the
// graph is queryable in Cypher - internet_exposed/crown_jewel drive the DB-side
// path finder). `SET n += {…}` does the property-merge contract for us (later
// writes win per key; omitted keys, e.g. an empty name, are preserved), so no
// read-modify-write round-trip is needed.
func (s *Store) UpsertNode(ctx context.Context, n ontology.Node) error {
	if !ontology.IsValidLabel(n.Label) {
		return fmt.Errorf("refusing to upsert node with unknown label %q", n.Label)
	}
	props := make(map[string]any, len(n.Properties)+1)
	for k, v := range n.Properties {
		props[k] = v
	}
	if n.Name != "" {
		props["name"] = n.Name // omitted when empty → a stub upsert never erases the stored name
	}

	inner := fmt.Sprintf(`MERGE (n:%s {id: %s})`, n.Label, cypherQuote(n.ID))
	if len(props) > 0 {
		inner += " SET n += " + cypherMap(props)
	}
	q, err := s.cypherSQL(inner, `v agtype`)
	if err != nil {
		return err
	}
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
		s.ensureLabelIndex(ctx, tx, n.Label)
		return nil
	})
}

// UpsertEdge creates or updates a directed relationship. When either endpoint
// is not in the graph yet, the MATCH yields no rows and the upsert returns an
// error instead of silently doing nothing: the normalization consumer Naks the
// event, and the broker redelivers it so the edge lands once its nodes arrive.
func (s *Store) UpsertEdge(ctx context.Context, e ontology.Edge) error {
	if !ontology.IsValidEdgeType(e.Type) {
		return fmt.Errorf("refusing to upsert edge with unknown type %q", e.Type)
	}
	// Native agtype edge properties, consistent with nodes: `p` (clamped) plus any
	// edge attributes, so they're queryable too (e.g. the privesc `primitives`).
	props := make(map[string]any, len(e.Properties)+1)
	for k, v := range e.Properties {
		props[k] = v
	}
	props["p"] = clampProb(e.ExploitProbability)
	inner := fmt.Sprintf(
		`MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[e:%s]->(b) SET e += %s RETURN 1`,
		cypherQuote(e.From), cypherQuote(e.To), e.Type, cypherMap(props))
	q, err := s.cypherSQL(inner, `v agtype`)
	if err != nil {
		return err
	}
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return fmt.Errorf("upsert edge %s %s->%s: endpoint node(s) not in graph yet", e.Type, e.From, e.To)
		}
		return rows.Err()
	})
}

func (s *Store) Snapshot(ctx context.Context) (graph.Snapshot, error) {
	var snap graph.Snapshot
	nodeQ, err := s.cypherSQL(`MATCH (n) RETURN n.id, label(n), n.name, properties(n)`,
		`id agtype, label agtype, name agtype, props agtype`)
	if err != nil {
		return snap, err
	}
	edgeQ, err := s.cypherSQL(`MATCH (a)-[e]->(b) RETURN type(e), a.id, b.id, properties(e)`,
		`etype agtype, src agtype, dst agtype, props agtype`)
	if err != nil {
		return snap, err
	}
	err = s.withAGE(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, nodeQ)
		if err != nil {
			return fmt.Errorf("query nodes: %w", err)
		}
		for rows.Next() {
			var id, label, name, props string
			if err := rows.Scan(&id, &label, &name, &props); err != nil {
				rows.Close()
				return err
			}
			snap.Nodes = append(snap.Nodes, ontology.Node{
				ID:         agString(id),
				Label:      ontology.Label(agString(label)),
				Name:       agString(name),
				Properties: nativeProps(props),
			})
		}
		rows.Close()

		erows, err := tx.QueryContext(ctx, edgeQ)
		if err != nil {
			return fmt.Errorf("query edges: %w", err)
		}
		defer erows.Close()
		for erows.Next() {
			var etype, src, dst, props string
			if err := erows.Scan(&etype, &src, &dst, &props); err != nil {
				return err
			}
			p, rest := edgeProps(props)
			snap.Edges = append(snap.Edges, ontology.Edge{
				Type:               ontology.EdgeType(agString(etype)),
				From:               agString(src),
				To:                 agString(dst),
				ExploitProbability: p,
				Properties:         rest,
			})
		}
		return erows.Err()
	})
	return snap, err
}

// SnapshotSince returns the nodes and edges whose last_seen stamp is at or after
// `since` (unix seconds) - the incremental delta the analyzer patches onto its
// cached snapshot instead of pulling the whole graph each pass. The filter runs
// natively (the same last_seen the pruner uses), so only the changed slice leaves
// Postgres. Elements without a last_seen are excluded (`null >= since` is false in
// Cypher) - they predate stamping and are already in the consumer's full snapshot.
func (s *Store) SnapshotSince(ctx context.Context, since int64) (graph.Delta, error) {
	var d graph.Delta
	nodeQ, err := s.cypherSQL(
		fmt.Sprintf(`MATCH (n) WHERE n.last_seen >= %d RETURN n.id, label(n), n.name, properties(n)`, since),
		`id agtype, label agtype, name agtype, props agtype`)
	if err != nil {
		return d, err
	}
	edgeQ, err := s.cypherSQL(
		fmt.Sprintf(`MATCH (a)-[e]->(b) WHERE e.last_seen >= %d RETURN type(e), a.id, b.id, properties(e)`, since),
		`etype agtype, src agtype, dst agtype, props agtype`)
	if err != nil {
		return d, err
	}
	err = s.withAGE(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, nodeQ)
		if err != nil {
			return fmt.Errorf("query nodes: %w", err)
		}
		for rows.Next() {
			var id, label, name, props string
			if err := rows.Scan(&id, &label, &name, &props); err != nil {
				rows.Close()
				return err
			}
			d.Nodes = append(d.Nodes, ontology.Node{
				ID:         agString(id),
				Label:      ontology.Label(agString(label)),
				Name:       agString(name),
				Properties: nativeProps(props),
			})
		}
		rows.Close()

		erows, err := tx.QueryContext(ctx, edgeQ)
		if err != nil {
			return fmt.Errorf("query edges: %w", err)
		}
		defer erows.Close()
		for erows.Next() {
			var etype, src, dst, props string
			if err := erows.Scan(&etype, &src, &dst, &props); err != nil {
				return err
			}
			p, rest := edgeProps(props)
			d.Edges = append(d.Edges, ontology.Edge{
				Type:               ontology.EdgeType(agString(etype)),
				From:               agString(src),
				To:                 agString(dst),
				ExploitProbability: p,
				Properties:         rest,
			})
		}
		return erows.Err()
	})
	return d, err
}

func (s *Store) Close() error { return s.db.Close() }

// ── DB-side path finding (the reason AGE exists) ────────────────────

// agVertex / agRel mirror AGE's JSON shape for nodes(p) / relationships(p)
// elements (each carries a `::vertex`/`::edge` text annotation we strip first).
type agVertex struct {
	Label      string         `json:"label"`
	Properties map[string]any `json:"properties"`
}
type agRel struct {
	Label      string         `json:"label"`
	Properties map[string]any `json:"properties"`
}

// Safety rails on the variable-length enumeration: openCypher `[*1..N]` lists ALL
// paths, which is potentially exponential on a cyclic/dense graph. A server-side
// statement_timeout cancels a runaway query (→ error → the caller falls back to
// the bounded in-process Dijkstra), and a LIMIT caps how many rows reach memory.
const (
	pathStatementTimeoutMs = "5000"
	maxPathsReturned       = 5000
)

// CriticalPaths finds internet-exposed → crown-jewel routes IN THE DATABASE via
// a Cypher variable-length match over the native node properties, bounded to
// maxHops. It returns up to maxPathsReturned such paths; the analyzer scores them
// and keeps the best per (source, target).
//
// NOTE: this enumerates paths (not a weighted shortest path, which AGE lacks), so
// it is best used for bounded/targeted queries; the analyzer uses the in-process
// Dijkstra by default and only calls this when explicitly opted in.
func (s *Store) CriticalPaths(ctx context.Context, maxHops int) ([]graph.RawPath, error) {
	if maxHops < 1 {
		maxHops = 12
	}
	if maxHops > 32 {
		maxHops = 32 // keep variable-length enumeration bounded
	}
	inner := fmt.Sprintf(
		`MATCH p=(a)-[*1..%d]->(b) `+
			`WHERE a.internet_exposed = true AND b.crown_jewel = true AND id(a) <> id(b) `+
			`RETURN nodes(p), relationships(p) LIMIT %d`, maxHops, maxPathsReturned)
	q, err := s.cypherSQL(inner, `ns agtype, rs agtype`)
	if err != nil {
		return nil, err
	}

	var out []graph.RawPath
	err = s.withAGE(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = "+pathStatementTimeoutMs); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ns, rs string
			if err := rows.Scan(&ns, &rs); err != nil {
				return err
			}
			if rp, ok := parseRawPath(ns, rs); ok {
				out = append(out, rp)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out) >= maxPathsReturned {
			slog.Warn("db pathfinder hit the path LIMIT; results may be incomplete - lower ANALYZER_MAX_HOPS or disable ANALYZER_DB_PATHS",
				"limit", maxPathsReturned)
		}
		return nil
	})
	return out, err
}

// Prune deletes nodes and edges whose last_seen stamp predates the cutoff,
// removing assets that fell out of the source feeds before they accrue into
// phantom attack paths. A missing last_seen is null in Cypher and `null < cutoff`
// is null (not true), so un-stamped elements are left alone. Deleting a node also
// detaches it (DETACH DELETE), so its edges go with it.
func (s *Store) Prune(ctx context.Context, before time.Time) (graph.PruneStats, error) {
	cutoff := before.Unix() // an int64 - safe to inline, no injection surface

	countNodes, err := s.cypherSQL(
		fmt.Sprintf("MATCH (n) WHERE n.last_seen < %d RETURN count(n)", cutoff), `c agtype`)
	if err != nil {
		return graph.PruneStats{}, err
	}
	countEdges, err := s.cypherSQL(
		fmt.Sprintf("MATCH ()-[e]->() WHERE e.last_seen < %d RETURN count(e)", cutoff), `c agtype`)
	if err != nil {
		return graph.PruneStats{}, err
	}
	delEdges, err := s.cypherSQL(
		fmt.Sprintf("MATCH ()-[e]->() WHERE e.last_seen < %d DELETE e", cutoff), `a agtype`)
	if err != nil {
		return graph.PruneStats{}, err
	}
	delNodes, err := s.cypherSQL(
		fmt.Sprintf("MATCH (n) WHERE n.last_seen < %d DETACH DELETE n", cutoff), `a agtype`)
	if err != nil {
		return graph.PruneStats{}, err
	}

	var stats graph.PruneStats
	err = s.withAGE(ctx, func(tx *sql.Tx) error {
		// Count what's stale before deleting (DETACH DELETE removes a node's
		// remaining edges silently; the edge count captures edges stale in their
		// own right). Then delete edges, then nodes.
		if stats.Nodes, err = scanCount(ctx, tx, countNodes); err != nil {
			return err
		}
		if stats.Edges, err = scanCount(ctx, tx, countEdges); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, delEdges); err != nil {
			return fmt.Errorf("prune edges: %w", err)
		}
		if _, err := tx.ExecContext(ctx, delNodes); err != nil {
			return fmt.Errorf("prune nodes: %w", err)
		}
		return nil
	})
	if err != nil {
		return graph.PruneStats{}, err
	}
	return stats, nil
}

// scanCount runs a Cypher `RETURN count(...)` query and reads the single agtype
// integer it returns.
func scanCount(ctx context.Context, tx *sql.Tx, query string) (int, error) {
	var raw string
	if err := tx.QueryRowContext(ctx, query).Scan(&raw); err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("parse count %q: %w", raw, err)
	}
	return n, nil
}

// stripAgtype removes AGE's `::vertex`/`::edge`/`::path` type annotations from an
// agtype text value, leaving valid JSON - but ONLY outside JSON strings, so a
// property value like "foo::vertex" survives intact (a naive global replace would
// silently corrupt it and drop the whole path).
func stripAgtype(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) { // keep the escaped char verbatim
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == ':' && i+1 < len(s) && s[i+1] == ':' {
			switch {
			case strings.HasPrefix(s[i:], "::vertex"):
				i += len("::vertex") - 1
				continue
			case strings.HasPrefix(s[i:], "::edge"):
				i += len("::edge") - 1
				continue
			case strings.HasPrefix(s[i:], "::path"):
				i += len("::path") - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func parseRawPath(ns, rs string) (graph.RawPath, bool) {
	var verts []agVertex
	if err := json.Unmarshal([]byte(stripAgtype(ns)), &verts); err != nil {
		return graph.RawPath{}, false
	}
	var rels []agRel
	if err := json.Unmarshal([]byte(stripAgtype(rs)), &rels); err != nil {
		return graph.RawPath{}, false
	}
	if len(verts) == 0 || len(rels) != len(verts)-1 {
		return graph.RawPath{}, false
	}

	rp := graph.RawPath{
		Nodes: make([]ontology.Node, 0, len(verts)),
		Edges: make([]ontology.Edge, 0, len(rels)),
	}
	for _, v := range verts {
		id, _ := v.Properties["id"].(string)
		name, _ := v.Properties["name"].(string)
		props := map[string]any{}
		for k, val := range v.Properties {
			if k != "id" && k != "name" {
				props[k] = val
			}
		}
		if len(props) == 0 {
			props = nil
		}
		rp.Nodes = append(rp.Nodes, ontology.Node{ID: id, Label: ontology.Label(v.Label), Name: name, Properties: props})
	}
	for i, r := range rels {
		p, _ := r.Properties["p"].(float64)
		rp.Edges = append(rp.Edges, ontology.Edge{
			Type:               ontology.EdgeType(r.Label),
			From:               rp.Nodes[i].ID,
			To:                 rp.Nodes[i+1].ID,
			ExploitProbability: p,
		})
	}
	return rp, true
}

// ensureLabelIndex creates a btree index on the label's `id` property the first
// time the process touches that label, turning the per-upsert `MATCH {id: …}`
// from a sequential scan into an index lookup. Best-effort: a failure is left to
// retry on the next upsert (the work still succeeds without the index).
func (s *Store) ensureLabelIndex(ctx context.Context, tx *sql.Tx, label ontology.Label) {
	if _, done := s.indexed.Load(label); done {
		return
	}
	idx := sanitizeIdent(fmt.Sprintf("%s_%s_id_idx", s.graph, strings.ToLower(string(label))))
	stmt := fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS "%s" ON "%s"."%s" USING btree (agtype_access_operator(properties, '"id"'::agtype))`,
		idx, s.graph, label)
	if _, err := tx.ExecContext(ctx, stmt); err == nil {
		s.indexed.Store(label, true)
	}
}

// withAGE runs fn inside a transaction that has AGE loaded and on the search path.
func (s *Store) withAGE(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `LOAD 'age'`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("load age: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SET search_path = ag_catalog, "$user", public`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("set search_path: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ── safe-SQL helpers ────────────────────────────────────────────────

// cypherSQL wraps a Cypher body in a cypher() call against this store's graph,
// using a randomized dollar-quote tag the body provably cannot contain.
func (s *Store) cypherSQL(inner, asSpec string) (string, error) {
	tag, err := dollarTag(inner)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("SELECT * FROM cypher('%s', %s %s %s) AS (%s)",
		s.graph, tag, inner, tag, asSpec), nil
}

// dollarTag returns a `$pg<rand>$` Postgres dollar-quote tag that does not occur
// in body, so body can never terminate the quoted literal early.
func dollarTag(body string) (string, error) {
	var b [9]byte
	for i := 0; i < 5; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		tag := "$pg" + hex.EncodeToString(b[:]) + "$"
		if !strings.Contains(body, tag) {
			return tag, nil
		}
	}
	return "", errors.New("age: could not generate a collision-free dollar-quote tag")
}

func cypherQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// cypherMap renders a property bag as a Cypher map literal with backtick-quoted
// keys (safe for any key, e.g. "repo-slug/x") and typed values. Keys are sorted
// for deterministic output.
func cypherMap(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('`')
		b.WriteString(strings.ReplaceAll(k, "`", "``"))
		b.WriteString("`:")
		b.WriteString(cypherValue(m[k]))
	}
	b.WriteByte('}')
	return b.String()
}

func cypherValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		return cypherQuote(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case json.Number:
		return x.String()
	default:
		// Arrays/maps/anything exotic: store as a JSON string - safe and
		// round-trippable as text (lossy on the original type, but rare here).
		b, err := json.Marshal(x)
		if err != nil {
			return "''"
		}
		return cypherQuote(string(b))
	}
}

// nativeProps parses an agtype properties() map and drops the reserved
// id/name/props keys (kept as separate fields), so Properties matches the
// in-memory store. For BACKWARD COMPATIBILITY it also merges a legacy `props`
// JSON string (the pre-migration storage format) underneath the native keys -
// native wins - so a graph written by an older build still yields correct
// seeds/jewels without a destructive reseed.
func nativeProps(raw string) map[string]any {
	m := unmarshalProps(raw)
	if m == nil {
		return nil
	}
	if legacy, ok := m["props"].(string); ok && legacy != "" {
		if old := unmarshalProps(legacy); old != nil {
			merged := make(map[string]any, len(old)+len(m))
			for k, v := range old {
				merged[k] = v
			}
			for k, v := range m { // native keys take precedence
				merged[k] = v
			}
			m = merged
		}
	}
	delete(m, "id")
	delete(m, "name")
	delete(m, "props") // legacy storage format
	delete(m, "label") // legacy: label is now intrinsic (label(n))
	if len(m) == 0 {
		return nil
	}
	return m
}

// edgeProps splits an agtype edge properties() map into its probability `p` and
// the remaining (backward-compatible) user properties.
func edgeProps(raw string) (float64, map[string]any) {
	m := nativeProps(raw)
	if m == nil {
		return 0, nil
	}
	var p float64
	if v, ok := m["p"].(float64); ok {
		p = v
	}
	delete(m, "p")
	if len(m) == 0 {
		m = nil
	}
	return p, m
}

func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func unmarshalProps(s string) map[string]any {
	if s == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// agString decodes an agtype scalar that holds a string (returned JSON-quoted).
func agString(raw string) string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return strings.Trim(raw, `"`)
}

func clampProb(p float64) float64 {
	if p <= 0 {
		return 0.01 // avoid log(0) downstream; unknown edges are still traversable
	}
	if p > 1 {
		return 1
	}
	return p
}
