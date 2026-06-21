// Package age implements graph.Store on top of PostgreSQL + Apache AGE.
//
// AGE exposes openCypher via the ag_catalog.cypher() set-returning function.
// Each session must LOAD 'age' and put ag_catalog on the search_path, so every
// operation runs inside a short transaction that performs that setup first.
//
// NOTE (MVP): values are inlined into the Cypher text with escaping rather than
// bound as parameters, because AGE's parameter passing is awkward. Labels and
// edge types come from the controlled ontology enum (never user input); only
// ids/names/properties are attacker-influenced and are escaped via cypherQuote.
// Hardening this with proper parameter binding is tracked in the roadmap.
package age

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
	_ "github.com/lib/pq"
)

type Store struct {
	db    *sql.DB
	graph string
}

// Open connects to Postgres and verifies the AGE extension + target graph are
// available. The pool is pinned to a single connection to keep AGE's
// session-scoped state (LOAD/search_path) predictable.
func Open(ctx context.Context, dsn, graphName string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db, graph: graphName}
	if err := s.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	// Confirm AGE is installed and the graph exists.
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, fmt.Sprintf(
			`SELECT * FROM cypher('%s', $aegis$ RETURN 1 $aegis$) AS (v agtype)`, s.graph))
		return err
	})
}

func (s *Store) UpsertNode(ctx context.Context, n ontology.Node) error {
	props := marshalProps(n.Properties)
	cypher := fmt.Sprintf(
		`MERGE (n:%s {id: %s}) SET n.label = %s, n.name = %s, n.props = %s`,
		n.Label,
		cypherQuote(n.ID),
		cypherQuote(string(n.Label)),
		cypherQuote(n.Name),
		cypherQuote(props),
	)
	return s.runCypher(ctx, cypher)
}

func (s *Store) UpsertEdge(ctx context.Context, e ontology.Edge) error {
	props := marshalProps(e.Properties)
	cypher := fmt.Sprintf(
		`MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[e:%s]->(b) SET e.p = %g, e.props = %s`,
		cypherQuote(e.From),
		cypherQuote(e.To),
		e.Type,
		clampProb(e.ExploitProbability),
		cypherQuote(props),
	)
	return s.runCypher(ctx, cypher)
}

func (s *Store) Snapshot(ctx context.Context) (graph.Snapshot, error) {
	var snap graph.Snapshot
	err := s.withAGE(ctx, func(tx *sql.Tx) error {
		// Nodes
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(
			`SELECT * FROM cypher('%s', $aegis$ MATCH (n) RETURN n.id, n.label, n.name, n.props $aegis$)
			 AS (id agtype, label agtype, name agtype, props agtype)`, s.graph))
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
				Properties: unmarshalProps(agString(props)),
			})
		}
		rows.Close()

		// Edges
		erows, err := tx.QueryContext(ctx, fmt.Sprintf(
			`SELECT * FROM cypher('%s', $aegis$ MATCH (a)-[e]->(b) RETURN type(e), a.id, b.id, e.p, e.props $aegis$)
			 AS (etype agtype, src agtype, dst agtype, p agtype, props agtype)`, s.graph))
		if err != nil {
			return fmt.Errorf("query edges: %w", err)
		}
		defer erows.Close()
		for erows.Next() {
			var etype, src, dst, p, props string
			if err := erows.Scan(&etype, &src, &dst, &p, &props); err != nil {
				return err
			}
			snap.Edges = append(snap.Edges, ontology.Edge{
				Type:               ontology.EdgeType(agString(etype)),
				From:               agString(src),
				To:                 agString(dst),
				ExploitProbability: agFloat(p),
				Properties:         unmarshalProps(agString(props)),
			})
		}
		return erows.Err()
	})
	return snap, err
}

func (s *Store) Close() error { return s.db.Close() }

// runCypher executes a write-style Cypher statement (no rows expected).
func (s *Store) runCypher(ctx context.Context, cypher string) error {
	return s.withAGE(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, fmt.Sprintf(
			`SELECT * FROM cypher('%s', $aegis$ %s $aegis$) AS (v agtype)`, s.graph, cypher))
		return err
	})
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

// ── helpers ─────────────────────────────────────────────────────────

func cypherQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func marshalProps(p map[string]any) string {
	if len(p) == 0 {
		return "{}"
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
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

// agFloat decodes an agtype numeric scalar.
func agFloat(raw string) float64 {
	var f float64
	if err := json.Unmarshal([]byte(raw), &f); err == nil {
		return f
	}
	return 0
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
