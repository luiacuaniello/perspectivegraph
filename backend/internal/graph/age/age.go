// Package age implements graph.Store on top of PostgreSQL + Apache AGE.
//
// AGE exposes openCypher via the ag_catalog.cypher() set-returning function.
// Each session needs the AGE library loaded and ag_catalog on the search_path, so
// every operation runs inside a short transaction that performs that setup first.
// How the library gets loaded depends on the server, and that difference decides
// whether this store works on a managed PostgreSQL at all - see resolveLoadMode.
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

	"github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// maxOpenConns sizes the connection pool. AGE session state (LOAD + search_path) is
// re-established at the start of every transaction (see withAGE), so any pooled
// connection is safe to use - there is no need to pin to one.
const maxOpenConns = 8

// pools shares one connection pool per DSN between the stores of every tenant.
//
// Each tenant's store used to open a pool of its own, so a replica's claim on the
// database grew by eight connections per tenant - and a tenant is created by the first
// write naming it, so the number of tenants, not the operator, set how many connections
// the deployment needed. Ten tenants on three replicas were past PostgreSQL's default
// max_connections of 100. A graph is only a name inside one database, so they share.
var pools = struct {
	sync.Mutex
	byDSN map[string]*sharedPool
}{byDSN: map[string]*sharedPool{}}

type sharedPool struct {
	db   *sql.DB
	refs int
}

func acquirePool(dsn string) (*sql.DB, error) {
	pools.Lock()
	defer pools.Unlock()
	if p := pools.byDSN[dsn]; p != nil {
		p.refs++
		return p.db, nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	pools.byDSN[dsn] = &sharedPool{db: db, refs: 1}
	return db, nil
}

// releasePool drops one store's claim on its pool, closing the pool with the last one.
func releasePool(dsn string) error {
	pools.Lock()
	defer pools.Unlock()
	p := pools.byDSN[dsn]
	if p == nil {
		return nil
	}
	p.refs--
	if p.refs > 0 {
		return nil
	}
	delete(pools.byDSN, dsn)
	return p.db.Close()
}

// graphNameRe is the strict identifier pattern a graph name must match before it
// is interpolated into SQL. Tenant-derived names already pass through
// graph.NormalizeTenant; this is the fail-closed boundary check.
var graphNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Store struct {
	db        *sql.DB
	dsn       string
	graph     string
	closeOnce sync.Once

	// loadOnce resolves, at most once per store, how this server wants the AGE
	// library loaded; skipLoad and loadErr are its result and are read only after
	// it has run.
	loadOnce sync.Once
	skipLoad bool
	loadErr  error

	// indexed memoizes which label tables already have an id index this process,
	// so the (idempotent) CREATE INDEX runs at most once per label.
	indexed sync.Map

	// pendingReady records that the parked-edge table exists; see preparePending.
	pendingMu    sync.Mutex
	pendingReady bool
}

func newStore(dsn, graphName string) (*Store, error) {
	if !graphNameRe.MatchString(graphName) {
		return nil, fmt.Errorf("invalid graph name %q", graphName)
	}
	db, err := acquirePool(dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, dsn: dsn, graph: graphName}, nil
}

// Open connects to Postgres and verifies the AGE extension + target graph are
// available.
func Open(ctx context.Context, dsn, graphName string) (*Store, error) {
	s, err := newStore(dsn, graphName)
	if err != nil {
		return nil, err
	}
	if err := s.Ping(ctx); err != nil {
		_ = s.Close()
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
		_ = s.Close()
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

// UpsertNode creates or updates one vertex. It is a batch of one: see UpsertBatch.
func (s *Store) UpsertNode(ctx context.Context, n ontology.Node) error {
	return s.upsertBatch(ctx, []ontology.Node{n}, nil, false)
}

// UpsertEdge creates or updates one directed relationship. It is a batch of one that
// does not park: when either endpoint is not in the graph yet it returns an error
// wrapping graph.ErrEndpointsMissing instead of silently doing nothing.
func (s *Store) UpsertEdge(ctx context.Context, e ontology.Edge) error {
	return s.upsertBatch(ctx, nil, []ontology.Edge{e}, false)
}

// UpsertBatch writes nodes, then edges, in ONE transaction that holds this graph's
// write lock.
//
// One transaction per event rather than per element. Each element used to be its own
// transaction - BEGIN, LOAD, SET search_path, the statement, COMMIT - so an event paid
// five round trips and a commit for every node and edge it carried. Measured against
// the bundled Postgres, a 2,000-node event took ten seconds, a third of the time
// JetStream waits before redelivering it to another replica.
//
// The lock serialises writers to the same graph, across replicas. AGE has no unique
// constraint, so two transactions that MERGE the same id at once each see no vertex
// and each create one: measured, eight concurrent writers of the same fifty nodes left
// between ten and twenty-four duplicates, and the first write of a new label failed
// outright with "relation already exists" when two raced to create its table. Several
// backend replicas share one consumer and write concurrently, so an HA deployment met
// both. Nothing reads under this lock; only writers and the pruner wait on it.
//
// An edge whose endpoint is missing is parked (graph.EdgeParker) in the same transaction,
// and edges parked earlier for the nodes this batch writes are landed in it too - under
// the same lock, so a replica parking an edge and another writing its endpoint cannot
// miss each other.
func (s *Store) UpsertBatch(ctx context.Context, nodes []ontology.Node, edges []ontology.Edge) error {
	return s.upsertBatch(ctx, nodes, edges, true)
}

func (s *Store) upsertBatch(ctx context.Context, nodes []ontology.Node, edges []ontology.Edge, park bool) error {
	// Every statement is built before the transaction opens, so a value the store
	// refuses fails the event before anything is written.
	nodeQs := make([]nodeStmts, 0, len(nodes))
	labels := map[ontology.Label]bool{}
	for _, n := range nodes {
		q, err := s.nodeSQL(n)
		if err != nil {
			return err
		}
		nodeQs = append(nodeQs, q)
		labels[n.Label] = true
	}
	edgeQs := make([]string, 0, len(edges))
	for _, e := range edges {
		q, err := s.edgeSQL(e)
		if err != nil {
			return err
		}
		edgeQs = append(edgeQs, q)
	}

	s.prepareLabels(ctx, labels)
	if park {
		if err := s.preparePending(ctx); err != nil {
			return err
		}
	}

	var waiting []ontology.Edge
	err := s.withAGE(ctx, func(tx *sql.Tx) error {
		if err := s.lockForWrite(ctx, tx); err != nil {
			return err
		}
		// Every statement below looks vertices up by id, one at a time, so a nested loop
		// over the id indexes is always the right plan. The planner does not know that on
		// a graph whose statistics predate the rows it is writing - the first large event
		// into a new graph - and chose to sort the whole edge table for every edge instead,
		// which made that event quadratic in its size.
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_mergejoin = off`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_hashjoin = off`); err != nil {
			return err
		}
		for _, q := range nodeQs {
			// Update if the vertex exists, create it if not. Under the write lock nothing
			// else can create it in between, which is what MERGE could not promise.
			found, err := execReturnsRow(ctx, tx, q.update)
			if err != nil {
				return err
			}
			if !found {
				if _, err := tx.ExecContext(ctx, q.create); err != nil {
					return err
				}
			}
		}
		if park {
			// Edges parked for any node written above get their try first, so this
			// batch's own copy of the same edge, being newer, is the one that stays.
			if err := s.landParked(ctx, tx, nodes); err != nil {
				return err
			}
		}
		for i, q := range edgeQs {
			landed, err := execReturnsRow(ctx, tx, q)
			if err != nil {
				return err
			}
			if !landed {
				waiting = append(waiting, edges[i])
			}
		}
		if park {
			for _, e := range waiting {
				if err := s.parkEdge(ctx, tx, e, nil); err != nil {
					return err
				}
			}
			waiting = nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	return graph.EndpointsMissing(waiting)
}

// nodeStmts is the upsert of one vertex: update returns a row when the vertex existed,
// and create is run when it did not.
type nodeStmts struct{ update, create string }

// nodeSQL renders the upsert of one vertex with NATIVE agtype properties (so the graph
// is queryable in Cypher - internet_exposed/crown_jewel drive the DB-side path finder).
// `SET n += {…}` does the property-merge contract for us (later writes win per key;
// omitted keys, e.g. an empty name, are preserved), so no read-modify-write round-trip
// is needed.
//
// The id is matched with `WHERE n.id = …`, never with a property map. AGE turns
// `{id: …}` into a containment test (`properties @> …`) that the btree id index cannot
// serve, so every lookup written that way scanned the whole label table - this store
// created the index for years and never used it.
func (s *Store) nodeSQL(n ontology.Node) (nodeStmts, error) {
	if !ontology.IsValidLabel(n.Label) {
		return nodeStmts{}, fmt.Errorf("refusing to upsert node with unknown label %q", n.Label)
	}
	props := make(map[string]any, len(n.Properties)+1)
	for k, v := range n.Properties {
		props[k] = v
	}
	if n.Name != "" {
		props["name"] = n.Name // omitted when empty → a stub upsert never erases the stored name
	}
	set := ""
	if len(props) > 0 {
		set = " SET n += " + cypherMap(props)
	}
	update, err := s.cypherSQL(fmt.Sprintf(`MATCH (n:%s) WHERE n.id = %s%s RETURN 1`,
		n.Label, cypherQuote(n.ID), set), `v agtype`)
	if err != nil {
		return nodeStmts{}, err
	}
	create, err := s.cypherSQL(fmt.Sprintf(`CREATE (n:%s {id: %s})%s`,
		n.Label, cypherQuote(n.ID), set), `v agtype`)
	if err != nil {
		return nodeStmts{}, err
	}
	return nodeStmts{update: update, create: create}, nil
}

// edgeSQL renders the upsert of one relationship. It RETURNs a row only when both
// endpoints matched, which is how the caller tells a landed edge from a waiting one.
// Endpoints are matched with WHERE for the same reason as in nodeSQL.
func (s *Store) edgeSQL(e ontology.Edge) (string, error) {
	if !ontology.IsValidEdgeType(e.Type) {
		return "", fmt.Errorf("refusing to upsert edge with unknown type %q", e.Type)
	}
	// Native agtype edge properties, consistent with nodes: `p` (clamped) plus any
	// edge attributes, so they're queryable too (e.g. the privesc `primitives`).
	props := make(map[string]any, len(e.Properties)+1)
	for k, v := range e.Properties {
		props[k] = v
	}
	props["p"] = clampProb(e.ExploitProbability)
	inner := fmt.Sprintf(
		`MATCH (a), (b) WHERE a.id = %s AND b.id = %s MERGE (a)-[e:%s]->(b) SET e += %s RETURN 1`,
		cypherQuote(e.From), cypherQuote(e.To), e.Type, cypherMap(props))
	return s.cypherSQL(inner, `v agtype`)
}

// execReturnsRow runs q and reports whether it produced at least one row.
func execReturnsRow(ctx context.Context, tx *sql.Tx, q string) (bool, error) {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	got := rows.Next()
	if err := rows.Err(); err != nil {
		return false, err
	}
	return got, nil
}

// graphWriteLockClass namespaces the per-graph write lock. It uses the two-key form of
// the advisory lock, which PostgreSQL keeps apart from the single bigint keys the
// leader election, the audit chain and the migrations take, so the hash of a graph name
// can never collide with one of them. The value spells "PGWR".
const graphWriteLockClass = 0x50475752

// pendingTable is where parked edges wait, inside the graph's own schema: drop_graph
// takes it with the graph, and creating it needs no privilege on `public`, which
// PostgreSQL 15 stopped granting to every role.
const pendingTable = "_pg_pending_edges"

func (s *Store) pendingRef() string {
	return pq.QuoteIdentifier(s.graph) + "." + pq.QuoteIdentifier(pendingTable)
}

// preparePending creates the parked-edge table once per process, under the graph's write
// lock so replicas starting together do not race to create it.
func (s *Store) preparePending(ctx context.Context) error {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingReady {
		return nil
	}
	t, prefix := s.pendingRef(), sanitizeIdent(s.graph+"_pending")
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ` + t + ` (
			edge_type text NOT NULL,
			from_id   text NOT NULL,
			to_id     text NOT NULL,
			p         double precision NOT NULL,
			props     jsonb NOT NULL DEFAULT '{}',
			parked_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (edge_type, from_id, to_id))`,
		`CREATE INDEX IF NOT EXISTS ` + pq.QuoteIdentifier(prefix+"_from") + ` ON ` + t + ` (from_id)`,
		`CREATE INDEX IF NOT EXISTS ` + pq.QuoteIdentifier(prefix+"_to") + ` ON ` + t + ` (to_id)`,
		`CREATE INDEX IF NOT EXISTS ` + pq.QuoteIdentifier(prefix+"_at") + ` ON ` + t + ` (parked_at)`,
	}
	err := s.withAGE(ctx, func(tx *sql.Tx) error {
		if err := s.lockForWrite(ctx, tx); err != nil {
			return err
		}
		for _, q := range stmts {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("parked-edge table: %w", err)
			}
		}
		return nil
	})
	if err == nil {
		s.pendingReady = true
	}
	return err
}

// landParked retries the parked edges naming any of these nodes, and drops edges parked
// longer than graph.PendingEdgeTTL. An edge that still cannot land is parked again with
// its original time, so an unrelated node arriving does not keep it alive.
func (s *Store) landParked(ctx context.Context, tx *sql.Tx, nodes []ontology.Node) error {
	t := s.pendingRef()
	// #nosec G202 -- t is two quoted identifiers built from a validated graph name
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE parked_at < now() - make_interval(secs => $1)`,
		graph.PendingEdgeTTL.Seconds()); err != nil {
		return fmt.Errorf("expire parked edges: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	// #nosec G202 -- t is two quoted identifiers built from a validated graph name
	rows, err := tx.QueryContext(ctx, `DELETE FROM `+t+` WHERE from_id = ANY($1) OR to_id = ANY($1)
		RETURNING edge_type, from_id, to_id, p, props, parked_at`, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("take parked edges: %w", err)
	}
	type taken struct {
		edge ontology.Edge
		at   time.Time
	}
	var retry []taken
	for rows.Next() {
		var e ontology.Edge
		var typ, props string
		var at time.Time
		if err := rows.Scan(&typ, &e.From, &e.To, &e.ExploitProbability, &props, &at); err != nil {
			rows.Close()
			return err
		}
		e.Type = ontology.EdgeType(typ)
		e.Properties = decodeParkedProps(props)
		retry = append(retry, taken{e, at})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range retry {
		q, err := s.edgeSQL(r.edge)
		if err != nil {
			continue // only valid edges are ever parked; nothing to retry otherwise
		}
		landed, err := execReturnsRow(ctx, tx, q)
		if err != nil {
			return err
		}
		if !landed {
			at := r.at
			if err := s.parkEdge(ctx, tx, r.edge, &at); err != nil {
				return err
			}
		}
	}
	return nil
}

// parkEdge stores an edge to wait for its endpoint. A nil at means now: the edge was
// just observed, so a copy already waiting takes its newer properties and restarts its
// wait.
func (s *Store) parkEdge(ctx context.Context, tx *sql.Tx, e ontology.Edge, at *time.Time) error {
	props, err := json.Marshal(e.Properties)
	if err != nil {
		return err
	}
	if e.Properties == nil {
		props = []byte("{}")
	}
	// #nosec G202 -- the table reference is two quoted identifiers built from a validated graph name
	_, err = tx.ExecContext(ctx, `INSERT INTO `+s.pendingRef()+` (edge_type, from_id, to_id, p, props, parked_at)
		VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()))
		ON CONFLICT (edge_type, from_id, to_id) DO UPDATE
		SET p = EXCLUDED.p, props = EXCLUDED.props, parked_at = EXCLUDED.parked_at`,
		string(e.Type), e.From, e.To, e.ExploitProbability, string(props), at)
	if err != nil {
		return fmt.Errorf("park edge %s %s->%s: %w", e.Type, e.From, e.To, err)
	}
	return nil
}

// decodeParkedProps reads a parked edge's properties back with numbers kept as written:
// a unix last_seen decoded as float64 would render as 1.7e+09 in Cypher.
func decodeParkedProps(raw string) map[string]any {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || len(m) == 0 {
		return nil
	}
	return m
}

// PendingEdges implements graph.EdgeParker.
func (s *Store) PendingEdges(ctx context.Context, limit int) ([]ontology.Edge, int, error) {
	var exists sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, s.pendingRef()).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists.Valid {
		return nil, 0, nil // nothing was ever parked in this graph
	}
	t := s.pendingRef()
	var total int
	// #nosec G202 -- t is two quoted identifiers built from a validated graph name
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+t).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit < 0 {
		limit = total
	}
	// #nosec G202 -- t is two quoted identifiers built from a validated graph name
	rows, err := s.db.QueryContext(ctx, `SELECT edge_type, from_id, to_id, p, props FROM `+t+`
		ORDER BY parked_at, from_id, to_id, edge_type LIMIT $1`, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ontology.Edge
	for rows.Next() {
		var e ontology.Edge
		var typ, props string
		if err := rows.Scan(&typ, &e.From, &e.To, &e.ExploitProbability, &props); err != nil {
			return nil, 0, err
		}
		e.Type = ontology.EdgeType(typ)
		e.Properties = decodeParkedProps(props)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// lockForWrite takes this graph's write lock for the rest of the transaction.
func (s *Store) lockForWrite(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`,
		graphWriteLockClass, s.graph); err != nil {
		return fmt.Errorf("graph write lock: %w", err)
	}
	return nil
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
			var id, label, props string
			// name is NULL on a vertex written without one - a feed may send such a node
			// through /ingest/events - and scanning that into a string failed the WHOLE
			// snapshot: one nameless node took the dashboard and the analyzer down for the
			// tenant. An absent name reads as "".
			var name sql.NullString
			if err := rows.Scan(&id, &label, &name, &props); err != nil {
				rows.Close()
				return err
			}
			snap.Nodes = append(snap.Nodes, ontology.Node{
				ID:         agString(id),
				Label:      ontology.Label(agString(label)),
				Name:       agString(name.String),
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
			var id, label, props string
			// name is NULL on a vertex written without one - a feed may send such a node
			// through /ingest/events - and scanning that into a string failed the WHOLE
			// snapshot: one nameless node took the dashboard and the analyzer down for the
			// tenant. An absent name reads as "".
			var name sql.NullString
			if err := rows.Scan(&id, &label, &name, &props); err != nil {
				rows.Close()
				return err
			}
			d.Nodes = append(d.Nodes, ontology.Node{
				ID:         agString(id),
				Label:      ontology.Label(agString(label)),
				Name:       agString(name.String),
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

// Close releases this store's claim on the shared pool; the pool closes with the last.
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() { err = releasePool(s.dsn) })
	return err
}

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
		// Under the write lock, so a prune never interleaves with an event that is
		// writing an edge to a node this is deleting.
		if err := s.lockForWrite(ctx, tx); err != nil {
			return err
		}
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

// prepareLabels makes sure each label the write is about to use has its table and a
// btree index on its `id` property, turning the per-upsert `MATCH {id: …}` from a
// sequential scan into an index lookup. It runs once per label per process.
//
// It runs BEFORE the write, in a transaction of its own, and creates the label's table
// if no vertex of it exists yet - AGE otherwise creates it on the first MERGE, too late
// to index for the rest of the event. The first write of a label used to create the
// index inside the same transaction, right after its first vertex; doing it after the
// batch instead left a first 2,000-node event matching every vertex by sequential scan,
// measured slower than the per-element writes it replaced. And a failed statement
// aborts the transaction it is in, so an index that failed inside the write took the
// write down with it.
//
// Best-effort: a failure is logged and left to retry on the next write, which still
// succeeds without the index.
func (s *Store) prepareLabels(ctx context.Context, labels map[ontology.Label]bool) {
	for label := range labels {
		if _, done := s.indexed.Load(label); done {
			continue
		}
		// The label table is created with bound values. The index needs the names as
		// identifiers, which cannot be bound; they are validated ones (graphNameRe, the
		// ontology allowlist), so they are safe to interpolate there.
		const createLabel = `SELECT create_vlabel($1, $2) WHERE NOT EXISTS (
			SELECT 1 FROM ag_catalog.ag_label l JOIN ag_catalog.ag_graph g ON l.graph = g.graphid
			WHERE g.name = $3 AND l.name = $4)`
		idx := sanitizeIdent(fmt.Sprintf("%s_%s_id_idx", s.graph, strings.ToLower(string(label))))
		createIndex := fmt.Sprintf(
			`CREATE INDEX IF NOT EXISTS "%s" ON "%s"."%s" USING btree (agtype_access_operator(properties, '"id"'::agtype))`,
			idx, s.graph, label)
		err := s.withAGE(ctx, func(tx *sql.Tx) error {
			// Under the write lock: two replicas creating the same label table or index
			// at once is the race the lock exists for.
			if err := s.lockForWrite(ctx, tx); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, createLabel, s.graph, string(label), s.graph, string(label)); err != nil {
				return fmt.Errorf("create label: %w", err)
			}
			_, err := tx.ExecContext(ctx, createIndex)
			return err
		})
		if err != nil {
			slog.Warn("age: could not index a label; writes to it will scan until a later write succeeds",
				"graph", s.graph, "label", label, "err", err)
			continue
		}
		s.indexed.Store(label, true)
	}
}

// resolveLoadMode works out, once per store, whether this server needs an explicit
// `LOAD 'age'` at the start of every transaction.
//
// The classic AGE recipe is to LOAD per session, and that is what the bundled demo
// database wants - it connects as a superuser. PostgreSQL only lets a superuser LOAD
// a shared library, though, and NO managed PostgreSQL hands out superuser: on Azure
// Database for PostgreSQL, the one managed service that offers AGE at all, the role
// you get is not one and the library is preloaded through shared_preload_libraries
// instead. There `LOAD 'age'` fails with 42501 - and this store used to take that as
// fatal, which meant it could run on a laptop and on nothing a customer would buy.
//
// So a privilege error is not fatal on its own. It is fatal only if AGE also turns
// out to be unusable, which is what the probe settles.
func (s *Store) resolveLoadMode(ctx context.Context) error {
	s.loadOnce.Do(func() {
		var loadErr error
		if _, err := s.db.ExecContext(ctx, `LOAD 'age'`); err != nil {
			loadErr = err
		}
		s.skipLoad, s.loadErr = decideLoadMode(loadErr, func() error {
			// Casting to agtype calls a C function from the AGE library, so it
			// answers the only question that matters - "is AGE usable on this
			// connection?" - without needing a graph to exist yet. The value is
			// scanned as nullable and then discarded: what is being tested is
			// whether the call errors, and an agtype that renders as SQL NULL is
			// a working AGE, not a missing one.
			var probe sql.NullString
			return s.db.QueryRowContext(ctx, `SELECT '1'::ag_catalog.agtype::text`).Scan(&probe)
		})
	})
	return s.loadErr
}

// decideLoadMode turns the outcome of `LOAD 'age'` into a policy, and is kept
// separate from the database plumbing so both of its branches can be tested without
// a server that has AGE preloaded - a configuration a test container cannot easily
// produce.
func decideLoadMode(loadErr error, probe func() error) (skipLoad bool, err error) {
	if loadErr == nil {
		return false, nil
	}
	if !isInsufficientPrivilege(loadErr) {
		return false, fmt.Errorf("load age: %w", loadErr)
	}
	if probeErr := probe(); probeErr != nil {
		return false, fmt.Errorf(
			"this role may not LOAD the AGE library (%w) and AGE is not preloaded either (%v): "+
				"add `age` to shared_preload_libraries and restart the server (on Azure Database for "+
				"PostgreSQL, set the azure.extensions and shared_preload_libraries parameters), or "+
				"connect as a superuser", loadErr, probeErr)
	}
	slog.Info("age: library is preloaded; skipping per-transaction LOAD (this role may not LOAD)")
	return true, nil
}

// isInsufficientPrivilege reports whether err is PostgreSQL's 42501, which is what a
// non-superuser gets back from LOAD.
func isInsufficientPrivilege(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42501"
}

// withAGE runs fn inside a transaction that has AGE loaded and on the search path.
func (s *Store) withAGE(ctx context.Context, fn func(*sql.Tx) error) error {
	// Resolved before the work transaction opens, deliberately: a failed LOAD
	// aborts the transaction it runs in, so a probe that followed it there would
	// only ever report "current transaction is aborted".
	if err := s.resolveLoadMode(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if !s.skipLoad {
		if _, err := tx.ExecContext(ctx, `LOAD 'age'`); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("load age: %w", err)
		}
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
