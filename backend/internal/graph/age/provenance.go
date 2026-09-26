package age

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// provenanceTable records who asserted each element of the graph (graph.OriginWriter):
// one row per element, source and scope, with when the source last asserted it. It lives
// in the graph's schema beside the parked edges, for the same reasons: drop_graph takes
// it with the graph, and creating it needs no privilege on `public`.
//
// An element is a node (kind 'n', a = id) or an edge (kind 'e', a = type, b = from,
// c = to). Nodes and edges are keyed apart rather than by one encoded string, because an
// id arriving through /ingest/events may contain any character a separator would use.
const provenanceTable = "_pg_provenance"

// removalsTable holds the graph's removal epoch (graph.RemovalEpocher): one row, moved by
// every prune and sweep that took something out, whichever replica ran it.
const removalsTable = "_pg_removals"

// legacySource names the origin every element present when provenance began is given:
// someone asserted it, nobody recorded who. Its scope is empty, so no sweep retracts it -
// only staleness pruning can take such an element.
const legacySource = ""

type elemKey struct{ kind, a, b, c string }

func nodeKey(id string) elemKey { return elemKey{kind: "n", a: id} }

func edgeKey(e ontology.Edge) elemKey {
	return elemKey{kind: "e", a: string(e.Type), b: e.From, c: e.To}
}

func (s *Store) provRef() string {
	return pq.QuoteIdentifier(s.graph) + "." + pq.QuoteIdentifier(provenanceTable)
}

func (s *Store) removalsRef() string {
	return pq.QuoteIdentifier(s.graph) + "." + pq.QuoteIdentifier(removalsTable)
}

// prepareProvenance creates the provenance and removal-epoch tables once per process,
// under the graph's write lock so replicas starting together do not race.
//
// The first time the provenance table is created in a graph, every element already there
// is given the legacy origin. Without it, an element written before provenance existed
// and asserted again afterwards by one complete source would look owned by that source
// alone, and a later snapshot of it would remove something another feed - one that has
// not been back since the upgrade - still reports.
func (s *Store) prepareProvenance(ctx context.Context) error {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	if s.provReady {
		return nil
	}
	if err := s.preparePending(ctx); err != nil { // the backfill reads it
		return err
	}
	t, r, prefix := s.provRef(), s.removalsRef(), sanitizeIdent(s.graph+"_prov")
	nodeQ, err := s.cypherSQL(`MATCH (n) RETURN n.id`, `id agtype`)
	if err != nil {
		return err
	}
	edgeQ, err := s.cypherSQL(`MATCH (a)-[e]->(b) RETURN type(e), a.id, b.id`, `etype agtype, src agtype, dst agtype`)
	if err != nil {
		return err
	}
	err = s.withAGE(ctx, func(tx *sql.Tx) error {
		if err := s.lockForWrite(ctx, tx); err != nil {
			return err
		}
		var existed sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, t).Scan(&existed); err != nil {
			return err
		}
		for _, q := range []string{
			`CREATE TABLE IF NOT EXISTS ` + t + ` (
				kind    text NOT NULL,
				a       text NOT NULL,
				b       text NOT NULL DEFAULT '',
				c       text NOT NULL DEFAULT '',
				source  text NOT NULL,
				scope   text NOT NULL DEFAULT '',
				seen_at timestamptz NOT NULL,
				PRIMARY KEY (kind, a, b, c, source, scope))`,
			`CREATE INDEX IF NOT EXISTS ` + pq.QuoteIdentifier(prefix+"_scope") + ` ON ` + t + ` (source, scope, seen_at)`,
			`CREATE INDEX IF NOT EXISTS ` + pq.QuoteIdentifier(prefix+"_seen") + ` ON ` + t + ` (seen_at)`,
			`CREATE TABLE IF NOT EXISTS ` + r + ` (epoch bigint NOT NULL)`,
			// #nosec G202 -- r is two quoted identifiers built from a validated graph name
			`INSERT INTO ` + r + ` (epoch) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM ` + r + `)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("provenance table: %w", err)
			}
		}
		if existed.Valid {
			return nil
		}
		// First time in this graph: everything already here predates provenance.
		var legacy []elemKey
		rows, err := tx.QueryContext(ctx, nodeQ)
		if err != nil {
			return fmt.Errorf("provenance backfill: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			legacy = append(legacy, nodeKey(agString(id)))
		}
		rows.Close()
		erows, err := tx.QueryContext(ctx, edgeQ)
		if err != nil {
			return fmt.Errorf("provenance backfill: %w", err)
		}
		for erows.Next() {
			var typ, from, to string
			if err := erows.Scan(&typ, &from, &to); err != nil {
				erows.Close()
				return err
			}
			legacy = append(legacy, elemKey{kind: "e", a: agString(typ), b: agString(from), c: agString(to)})
		}
		erows.Close()
		// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
		prows, err := tx.QueryContext(ctx, `SELECT edge_type, from_id, to_id FROM `+s.pendingRef())
		if err != nil {
			return fmt.Errorf("provenance backfill: %w", err)
		}
		for prows.Next() {
			k := elemKey{kind: "e"}
			if err := prows.Scan(&k.a, &k.b, &k.c); err != nil {
				prows.Close()
				return err
			}
			legacy = append(legacy, k)
		}
		prows.Close()
		return s.insertOrigins(ctx, tx, legacy, graph.Origin{Source: legacySource, Seen: time.Now()})
	})
	if err == nil {
		s.provReady = true
	}
	return err
}

// recordOrigins records o on every node and edge of a write.
func (s *Store) recordOrigins(ctx context.Context, tx *sql.Tx, o graph.Origin, nodes []ontology.Node, edges []ontology.Edge) error {
	keys := make([]elemKey, 0, len(nodes)+len(edges))
	for _, n := range nodes {
		keys = append(keys, nodeKey(n.ID))
	}
	for _, e := range edges {
		keys = append(keys, edgeKey(e))
	}
	return s.insertOrigins(ctx, tx, keys, o)
}

// insertOrigins writes one provenance row per key, keeping the latest time on conflict.
// Keys are deduplicated first: ON CONFLICT DO UPDATE refuses to touch one row twice in a
// statement, and an event may list the same node twice.
func (s *Store) insertOrigins(ctx context.Context, tx *sql.Tx, keys []elemKey, o graph.Origin) error {
	if len(keys) == 0 {
		return nil
	}
	seen := make(map[elemKey]bool, len(keys))
	var kinds, as, bs, cs []string
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		kinds, as, bs, cs = append(kinds, k.kind), append(as, k.a), append(bs, k.b), append(cs, k.c)
	}
	t := s.provRef()
	// #nosec G202 -- t is two quoted identifiers built from a validated graph name
	_, err := tx.ExecContext(ctx, `INSERT INTO `+t+` (kind, a, b, c, source, scope, seen_at)
		SELECT u.kind, u.a, u.b, u.c, $5, $6, $7
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS u(kind, a, b, c)
		ON CONFLICT (kind, a, b, c, source, scope) DO UPDATE
		SET seen_at = GREATEST(`+t+`.seen_at, EXCLUDED.seen_at)`,
		pq.Array(kinds), pq.Array(as), pq.Array(bs), pq.Array(cs), o.Source, o.Scope, o.Seen)
	if err != nil {
		return fmt.Errorf("record origins: %w", err)
	}
	return nil
}

// forgetOrigins drops every provenance row of these elements - they left the graph by
// another way than a sweep. A no-op before the provenance table exists.
func (s *Store) forgetOrigins(ctx context.Context, tx *sql.Tx, keys []elemKey) error {
	if len(keys) == 0 {
		return nil
	}
	var exists sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, s.provRef()).Scan(&exists); err != nil || !exists.Valid {
		return err
	}
	var kinds, as, bs, cs []string
	for _, k := range keys {
		kinds, as, bs, cs = append(kinds, k.kind), append(as, k.a), append(bs, k.b), append(cs, k.c)
	}
	// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
	_, err := tx.ExecContext(ctx, `DELETE FROM `+s.provRef()+` p
		USING unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS u(kind, a, b, c)
		WHERE p.kind = u.kind AND p.a = u.a AND p.b = u.b AND p.c = u.c`,
		pq.Array(kinds), pq.Array(as), pq.Array(bs), pq.Array(cs))
	return err
}

// bumpRemovals moves the removal epoch, in the transaction that removed something.
func (s *Store) bumpRemovals(ctx context.Context, tx *sql.Tx) error {
	// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
	if _, err := tx.ExecContext(ctx, `UPDATE `+s.removalsRef()+` SET epoch = epoch + 1`); err != nil {
		return fmt.Errorf("removal epoch: %w", err)
	}
	return nil
}

// RemovalEpoch implements graph.RemovalEpocher. A graph nothing was ever removed from,
// or that predates the epoch, reads 0.
func (s *Store) RemovalEpoch(ctx context.Context) (int64, error) {
	var exists sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, s.removalsRef()).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists.Valid {
		return 0, nil
	}
	var epoch int64
	// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(max(epoch), 0) FROM `+s.removalsRef()).Scan(&epoch)
	return epoch, err
}

// Sweep implements graph.Sweeper, in one transaction under the graph's write lock: the
// origin is withdrawn, the elements it leaves unasserted are removed, and the edges other
// sources still assert that joined a removed node are parked.
func (s *Store) Sweep(ctx context.Context, source, scope string, taken time.Time) (graph.SweepStats, error) {
	if scope == "" {
		return graph.SweepStats{}, graph.ErrEmptyScope
	}
	if err := s.prepareProvenance(ctx); err != nil {
		return graph.SweepStats{}, err
	}
	var stats graph.SweepStats
	err := s.withAGE(ctx, func(tx *sql.Tx) error {
		if err := s.lockForWrite(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_mergejoin = off`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_hashjoin = off`); err != nil {
			return err
		}
		t := s.provRef()
		// #nosec G202 -- t is two quoted identifiers built from a validated graph name
		rows, err := tx.QueryContext(ctx, `DELETE FROM `+t+` p
			WHERE p.source = $1 AND p.scope = $2 AND p.seen_at < $3
			AND NOT EXISTS (SELECT 1 FROM `+t+` o WHERE o.kind = p.kind AND o.a = p.a AND o.b = p.b AND o.c = p.c
				AND NOT (o.source = $1 AND o.scope = $2))
			RETURNING p.kind, p.a, p.b, p.c`, source, scope, taken)
		if err != nil {
			return fmt.Errorf("sweep: %w", err)
		}
		var nodes, edges []elemKey
		for rows.Next() {
			var k elemKey
			if err := rows.Scan(&k.kind, &k.a, &k.b, &k.c); err != nil {
				rows.Close()
				return err
			}
			if k.kind == "n" {
				nodes = append(nodes, k)
			} else {
				edges = append(edges, k)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// Rows of elements someone else still asserts: only this origin's claim goes.
		// #nosec G202 -- t is two quoted identifiers built from a validated graph name
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE source = $1 AND scope = $2 AND seen_at < $3`,
			source, scope, taken); err != nil {
			return fmt.Errorf("sweep: %w", err)
		}

		gone := map[elemKey]bool{}
		for _, k := range edges {
			gone[k] = true
			n, err := s.removeEdge(ctx, tx, k)
			if err != nil {
				return err
			}
			stats.Edges += n
		}
		for _, k := range nodes {
			removed, err := s.removeNode(ctx, tx, k.a, gone, &stats)
			if err != nil {
				return err
			}
			if removed {
				stats.Nodes++
			}
		}
		if stats.Removed() {
			return s.bumpRemovals(ctx, tx)
		}
		return nil
	})
	if err != nil {
		return graph.SweepStats{}, err
	}
	return stats, nil
}

// removeEdge deletes one edge, from the graph or from the parked edges, and reports how
// many copies it removed.
func (s *Store) removeEdge(ctx context.Context, tx *sql.Tx, k elemKey) (int, error) {
	if !ontology.IsValidEdgeType(ontology.EdgeType(k.a)) {
		return 0, nil // only valid edges are ever written; nothing to remove otherwise
	}
	q, err := s.cypherSQL(fmt.Sprintf(`MATCH (x)-[e:%s]->(y) WHERE x.id = %s AND y.id = %s DELETE e RETURN 1`,
		k.a, cypherQuote(k.b), cypherQuote(k.c)), `v agtype`)
	if err != nil {
		return 0, err
	}
	n := 0
	removed, err := execReturnsRow(ctx, tx, q)
	if err != nil {
		return 0, fmt.Errorf("sweep edge: %w", err)
	}
	if removed {
		n++
	}
	// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
	res, err := tx.ExecContext(ctx, `DELETE FROM `+s.pendingRef()+` WHERE edge_type = $1 AND from_id = $2 AND to_id = $3`,
		k.a, k.b, k.c)
	if err != nil {
		return 0, fmt.Errorf("sweep parked edge: %w", err)
	}
	if parked, _ := res.RowsAffected(); parked > 0 {
		n++
	}
	return n, nil
}

// removeNode deletes one node. Its edges go with it; each one another origin still
// asserts is parked instead, to land again if the node comes back.
func (s *Store) removeNode(ctx context.Context, tx *sql.Tx, id string, gone map[elemKey]bool, stats *graph.SweepStats) (bool, error) {
	qid := cypherQuote(id)
	var incident []ontology.Edge
	for _, pattern := range []string{
		`MATCH (x)-[e]->(y) WHERE x.id = %s RETURN type(e), x.id, y.id, properties(e)`,
		`MATCH (y)-[e]->(x) WHERE x.id = %s RETURN type(e), y.id, x.id, properties(e)`,
	} {
		q, err := s.cypherSQL(fmt.Sprintf(pattern, qid), `etype agtype, src agtype, dst agtype, props agtype`)
		if err != nil {
			return false, err
		}
		rows, err := tx.QueryContext(ctx, q)
		if err != nil {
			return false, fmt.Errorf("sweep node edges: %w", err)
		}
		for rows.Next() {
			var typ, from, to, props string
			if err := rows.Scan(&typ, &from, &to, &props); err != nil {
				rows.Close()
				return false, err
			}
			p, rest := edgeProps(props)
			incident = append(incident, ontology.Edge{Type: ontology.EdgeType(agString(typ)),
				From: agString(from), To: agString(to), ExploitProbability: p, Properties: rest})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}
	}
	for _, e := range incident {
		k := edgeKey(e)
		if gone[k] {
			continue
		}
		gone[k] = true
		var asserted bool
		// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+s.provRef()+`
			WHERE kind = 'e' AND a = $1 AND b = $2 AND c = $3)`, k.a, k.b, k.c).Scan(&asserted); err != nil {
			return false, err
		}
		if asserted {
			if err := s.parkEdge(ctx, tx, e, nil); err != nil {
				return false, err
			}
			stats.Parked++
		} else {
			stats.Edges++
		}
	}
	count, err := s.cypherSQL(fmt.Sprintf(`MATCH (n) WHERE n.id = %s RETURN count(n)`, qid), `c agtype`)
	if err != nil {
		return false, err
	}
	n, err := scanCount(ctx, tx, count)
	if err != nil || n == 0 {
		return false, err
	}
	del, err := s.cypherSQL(fmt.Sprintf(`MATCH (n) WHERE n.id = %s DETACH DELETE n`, qid), `a agtype`)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, del); err != nil {
		return false, fmt.Errorf("sweep node: %w", err)
	}
	return true, nil
}
