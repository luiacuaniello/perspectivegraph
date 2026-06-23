// Minimal GraphQL client for the PerspectiveGraph BFF. In dev, requests to /graphql
// are proxied to the Go backend by Vite (see vite.config.ts).

const ENDPOINT = "/graphql";

export interface Node {
  id: string;
  label: string;
  name: string;
  internetExposed: boolean;
  crownJewel: boolean;
  crownJewelBasis?: string | null;
  classification?: string | null;
  // True when a secret value was redacted out of this node's properties at ingest
  // (data hygiene - the attack map keeps the finding, not the credential).
  secretsScrubbed?: boolean | null;
  runtimeAlert: boolean;
  severity?: string | null;
  cvss?: number | null;
  kev?: boolean | null;
  epss?: number | null;
  // Identity-resolution provenance: set when this node's identity/join was
  // *inferred* by the resolver. resolutionConfidence < 1 ⇒ a heuristic
  // correlation an analyst should verify.
  resolutionMethod?: string | null;
  resolutionConfidence?: number | null;
  resolutionAlias?: string | null;
  // Supply-chain trust (images). signed: null = never assessed, false = verified
  // unsigned (a tampering vector), true = signature verified.
  signed?: boolean | null;
  slsaLevel?: number | null;
  sbomComponents?: number | null;
}

// AttackTechnique is the MITRE ATT&CK technique a hop maps to (heuristic).
export interface AttackTechnique {
  id: string; // e.g. T1190 or T1078.004
  name: string;
  tactic: string;
  tacticId: string;
  url: string;
}

export interface Edge {
  type: string;
  from: string;
  to: string;
  probability: number;
  attack?: AttackTechnique | null;
}

export interface Step {
  edgeType: string;
  from: string;
  to: string;
  probability: number;
  // Set when this hop's join was inferred by the resolver (e.g. container→image).
  // resolutionConfidence < 1 ⇒ a heuristic correlation to verify.
  resolutionMethod?: string | null;
  resolutionConfidence?: number | null;
  // Where this hop's probability came from: kev|epss|runtime (evidence) vs
  // cvss|severity|heuristic (estimate), and how much to trust it.
  weightBasis?: string | null;
  weightConfidence?: number | null;
  // MITRE ATT&CK technique this hop corresponds to (null for structural hops).
  attack?: AttackTechnique | null;
}

export interface Remediation {
  title: string;
  kind: string;
  filename: string;
  rationale: string;
  content: string;
}

export interface Detection {
  kind: string; // "falco" | "sigma"
  title: string;
  filename: string;
  content: string;
  rationale: string;
}

// Reason is the closed set of triage dispositions (mirrors internal/suppress).
export type SuppressionReason =
  | "accept-risk"
  | "false-positive"
  | "mitigating-control"
  | "duplicate";

export interface Suppression {
  reason: SuppressionReason;
  owner: string;
  note?: string | null;
  createdAt: string;
  expiresAt?: string | null;
}

// RemediationEffect is the verified, simulated impact of applying a fix.
export interface RemediationEffect {
  removedEdges: number;
  pathsBefore: number;
  pathsAfter: number;
  pathsEliminated: number;
  riskReductionPct: number;
  verified: boolean;
}

export interface Ticket {
  id: string;
  owner: string;
  title?: string;
  status: "open" | "closed";
  externalUrl?: string | null;
  createdAt?: string;
}

export type ValidationOutcome = "confirmed" | "refuted" | "partial" | "missed";

export interface Validation {
  outcome: ValidationOutcome;
  source: string;
  evidence?: string | null;
  testedAt?: string;
}

export interface ValidationMetrics {
  confirmed: number;
  refuted: number;
  partial: number;
  missed: number;
  tested: number;
  precision?: number | null; // null until any confirmed/refuted
  recall?: number | null; // null until any confirmed/missed
}

export interface AttackPath {
  id: string;
  score: number;
  runtimeConfirmed: boolean;
  // How much to trust `score` given how its edge weights were derived, and the
  // qualitative band (high|medium|low) - honesty about probability provenance.
  confidence?: number | null;
  confidenceLabel?: string | null;
  // Independence honesty: `score` is the product of the hops (assumes they're
  // independent). `scoreUpperBound` is the weakest hop - the score if the hops
  // share a common cause - so the true exploitability lies in [score, upper].
  // `correlatedHops` flags when two hops rest on the same basis (band is real).
  scoreUpperBound?: number | null;
  correlatedHops?: boolean | null;
  // Composite triage priority [0,100] (P1/P2/P3) with explainable factors -
  // paths arrive priority-first, so the list leads with what to fix today.
  priority?: number | null;
  priorityLabel?: string | null;
  priorityFactors?: string[] | null;
  nodes: Node[];
  steps: Step[];
  remediations: Remediation[];
  detections: Detection[];
  // Closed-loop: the open remediation ticket for this path, if any.
  ticket?: Ticket | null;
  // Validation: the latest red-team/BAS verdict on whether this path is real.
  validation?: Validation | null;
  // Triage: set when an analyst has taken this path off the active board.
  suppressed?: boolean;
  suppression?: Suppression | null;
  // Temporal (from the history store): how long this path has been open and
  // whether it's a regression (resolved then came back). Null until history has
  // recorded a pass.
  firstSeen?: string | null;
  openForSeconds?: number | null;
  reopens?: number | null;
}

export interface Posture {
  criticalPaths: number;
  activePaths: number;
  suppressedPaths: number;
  runtimeConfirmed: number;
  kevOnPaths: number;
  policyViolations: number;
  nodes: number;
  edges: number;
}

export interface CrownJewelRisk {
  id: string;
  name: string;
  label: string;
  compromiseProbability: number;
  ciLow: number;
  ciHigh: number;
}

export interface RiskSimulation {
  iterations: number;
  anyCompromiseProbability: number;
  anyCiLow: number;
  anyCiHigh: number;
  // Sensitivity band: any-compromise probability with edge probabilities scaled
  // ∓30% - reflects model/input uncertainty, not sampling.
  sensitivityLow: number;
  sensitivityHigh: number;
  expectedCompromised: number;
  crownJewels: CrownJewelRisk[];
}

export interface Violation {
  invariantId: string;
  description: string;
  severity: string;
  nodes: Node[];
}

export interface SearchHit {
  id: string;
  label: string;
  name: string;
  score: number;
}

export interface Fix {
  title: string;
  kind: string;
  filename: string;
  content: string;
  rationale: string;
  pathCount: number;
  riskCovered: number;
  coveragePct: number;
  // Independently simulated proof the fix works (what-if).
  verification?: RemediationEffect | null;
}

export interface PosturePoint {
  at: string;
  criticalPaths: number;
  riskPct: number;
}

export interface History {
  trend: PosturePoint[];
  openPaths: number;
  resolvedPaths: number;
  mttrSeconds?: number | null;
  oldestOpenSince?: string | null;
  persistent: boolean;
}

export interface Dashboard {
  posture: Posture;
  riskSimulation: RiskSimulation;
  searchEnabled: boolean;
  aiEnabled: boolean;
  applications: string[];
  attackPaths: AttackPath[];
  remediationPlan: Fix[];
  invariantViolations: Violation[];
  validation: ValidationMetrics;
  graph: { nodes: Node[]; edges: Edge[] };
}

export interface EdgeCut {
  from: string;
  to: string;
  type?: string;
}

export interface WhatIfResult {
  removedEdges: number;
  riskReduction: number;
  beforeRisk: { anyCompromiseProbability: number };
  afterRisk: { anyCompromiseProbability: number };
  after: { id: string }[];
}

const NODE_FIELDS = `id label name internetExposed crownJewel crownJewelBasis classification secretsScrubbed runtimeAlert severity cvss kev epss resolutionMethod resolutionConfidence resolutionAlias signed slsaLevel sbomComponents`;

// The graph is environment-wide; passing an app scopes attack paths and the
// graph view to one application (repo slug or cloud `app` tag). Posture and
// violations stay global on purpose - they are the whole-environment summary.
const dashboardQuery = (app?: string) => {
  const scope = app ? `(app: ${JSON.stringify(app)})` : "";
  return `
  query Dashboard {
    posture { criticalPaths activePaths suppressedPaths runtimeConfirmed kevOnPaths policyViolations nodes edges }
    riskSimulation {
      iterations anyCompromiseProbability anyCiLow anyCiHigh
      sensitivityLow sensitivityHigh expectedCompromised
      crownJewels { id name label compromiseProbability ciLow ciHigh }
    }
    searchEnabled
    aiEnabled
    applications
    attackPaths${scope} {
      id
      score
      runtimeConfirmed
      confidence
      confidenceLabel
      scoreUpperBound
      correlatedHops
      priority
      priorityLabel
      priorityFactors
      suppressed
      suppression { reason owner note createdAt expiresAt }
      firstSeen openForSeconds reopens
      ticket { id owner status externalUrl }
      validation { outcome source evidence testedAt }
      nodes { ${NODE_FIELDS} }
      steps { edgeType from to probability resolutionMethod resolutionConfidence weightBasis weightConfidence attack { id name tactic tacticId url } }
      remediations { title kind filename rationale content }
      detections { kind title filename rationale content }
    }
    remediationPlan${scope} {
      title kind filename rationale content pathCount riskCovered coveragePct
      verification { removedEdges pathsBefore pathsAfter pathsEliminated riskReductionPct verified }
    }
    invariantViolations {
      invariantId
      description
      severity
      nodes { ${NODE_FIELDS} }
    }
    validation { precision recall confirmed refuted partial missed tested }
    graph${scope} {
      nodes { ${NODE_FIELDS} }
      edges { type from to probability attack { id tactic } }
    }
  }
`;
};

// Auth credential. A runtime token set via the login gate (stored in
// sessionStorage, so it dies with the tab) takes precedence over the build-time
// VITE_API_TOKEN - so the dashboard is deployed once and users sign in at
// runtime instead of baking a token into the bundle.
const TOKEN_KEY = "pg-token";
const BUILD_TOKEN = import.meta.env.VITE_API_TOKEN as string | undefined;

export function authToken(): string | undefined {
  try {
    const t = sessionStorage.getItem(TOKEN_KEY);
    if (t) return t;
  } catch {
    /* sessionStorage unavailable - fall back to the build-time token */
  }
  return BUILD_TOKEN;
}

export function setAuthToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* ignore */
  }
}

export function clearAuthToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

// hasRuntimeToken reports whether the user signed in at runtime (vs an open API
// or a build-time token), so the UI can show a "sign out" control only then.
export function hasRuntimeToken(): boolean {
  try {
    return !!sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return false;
  }
}

// AuthConfig is the public /auth/config payload that drives the login gate.
export interface AuthConfig {
  authRequired: boolean;
  mode: "none" | "token" | "oidc" | "both";
  oidc?: {
    issuer?: string;
    audience?: string;
    clientId?: string;
    authorizeUrl?: string;
    tokenUrl?: string;
    scopes?: string;
  } | null;
}

export async function fetchAuthConfig(): Promise<AuthConfig> {
  const res = await fetch("/auth/config", { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`auth config: ${res.status}`);
  return res.json();
}

async function gql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = authToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers,
    body: JSON.stringify(variables ? { query, variables } : { query }),
  });
  if (!res.ok) throw new Error(`GraphQL HTTP ${res.status}`);
  const body = await res.json();
  if (body.errors?.length) throw new Error(body.errors[0].message);
  return body.data as T;
}

// humanDuration renders a seconds count as a compact, human "5m" / "3h" / "4.2d".
export function humanDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = seconds / 60;
  if (m < 60) return `${Math.round(m)}m`;
  const h = m / 60;
  if (h < 48) return `${Math.round(h)}h`;
  const d = h / 24;
  return `${d < 10 ? d.toFixed(1) : Math.round(d)}d`;
}

// Same-origin download URLs for the SIEM (NDJSON) and compliance (OSCAL) exports.
export const exportUrl = (kind: "ndjson" | "oscal") => `/export/${kind}`;

// What-if: simulate cutting one or more edges and get the residual quantified
// risk + surviving paths. Uses GraphQL variables so node names with quotes are safe.
export const runWhatIf = (cuts: EdgeCut[]) =>
  gql<{ whatIf: WhatIfResult }>(
    `query WhatIf($cuts: [EdgeCutInput!]!) {
       whatIf(cuts: $cuts) {
         removedEdges riskReduction
         beforeRisk { anyCompromiseProbability }
         afterRisk { anyCompromiseProbability }
         after { id }
       }
     }`,
    { cuts },
  ).then((d) => d.whatIf);

export const fetchDashboard = (app?: string) => gql<Dashboard>(dashboardQuery(app));

export interface Status {
  version: string;
  passes: number;
  paths: number;
  analyzedAt: string;
  // Staleness pruning (zero / null when GRAPH_TTL pruning is off).
  prunedNodes: number;
  prunedEdges: number;
  lastPrunedAt?: string | null;
}

// A cheap fingerprint of the analysis state. The dashboard polls this and only
// refetches the (heavy) full dashboard when it changes - instead of re-pulling
// the whole graph every few seconds.
export const fetchStatus = () =>
  gql<{ status: Status }>(
    `query Status { status { version passes paths analyzedAt prunedNodes prunedEdges lastPrunedAt } }`,
  ).then((d) => d.status);

// The temporal view (trend + MTTR + aging). Polled on its own light cadence so
// the exposure trend stays live even when the graph (and the heavy dashboard)
// hasn't changed - the trend evolving over a steady graph is itself the point.
export const fetchHistory = (points = 240) =>
  gql<{ history: History }>(
    `query History { history(points: ${points}) { openPaths resolvedPaths mttrSeconds oldestOpenSince persistent trend { at criticalPaths riskPct } } }`,
  ).then((d) => d.history);

// Full-text search over the optional OpenSearch index. With the index disabled
// the backend returns an empty list.
export const searchAssets = (query: string, size = 25) =>
  gql<{ search: SearchHit[] | null }>(
    `query Search { search(query: ${JSON.stringify(query)}, size: ${size}) { id label name score } }`,
  ).then((d) => d.search ?? []);

// ── Triage / suppression (REST) ─────────────────────────────────────
// The suppression board is a small REST surface (not GraphQL): GET to list,
// POST to record a decision, DELETE to un-suppress. Same bearer auth as gql.

export interface SuppressionRecord extends Suppression {
  pathId: string;
  tenant: string;
}

export interface SuppressionInput {
  pathId: string;
  reason: SuppressionReason;
  owner: string;
  note?: string;
  // Optional expiry: ttlDays is the convenience the UI uses; after it lapses the
  // path returns to the active board automatically.
  ttlDays?: number;
}

async function rest<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init?.headers as Record<string, string>) };
  const token = authToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const fetchSuppressions = () =>
  rest<{ suppressions: SuppressionRecord[] | null; persistent: boolean }>("/suppressions").then((b) => ({
    suppressions: b.suppressions ?? [],
    persistent: b.persistent,
  }));

export const createSuppression = (input: SuppressionInput) =>
  rest<SuppressionRecord>("/suppressions", { method: "POST", body: JSON.stringify(input) });

export const deleteSuppression = (pathId: string) =>
  rest<void>(`/suppressions/${encodeURIComponent(pathId)}`, { method: "DELETE" });

// ── Remediation ticketing (REST) ────────────────────────────────────

export interface TicketInput {
  pathId: string;
  owner: string;
  title?: string;
  route?: string;
}

export const createTicket = (input: TicketInput) =>
  rest<Ticket>("/tickets", { method: "POST", body: JSON.stringify(input) });

// openRemediationPR opens a pull request with this path's generated fix (branch +
// commit + PR). Requires GITHUB_TOKEN on the backend; admin role when auth is on.
export const openRemediationPR = (pathId: string) =>
  rest<{ url: string; files: number }>("/remediation/pr", {
    method: "POST",
    body: JSON.stringify({ pathId }),
  });

// AI-native layer (Claude). All require ANTHROPIC_API_KEY on the backend (else 503).
export const aiSummary = () => rest<{ answer: string }>("/ai/summary").then((r) => r.answer);

export const aiQuery = (question: string) =>
  rest<{ answer: string }>("/ai/query", { method: "POST", body: JSON.stringify({ question }) }).then(
    (r) => r.answer,
  );

export const aiExplain = (pathId: string) =>
  rest<{ answer: string }>("/ai/explain", { method: "POST", body: JSON.stringify({ pathId }) }).then(
    (r) => r.answer,
  );

export const closeTicket = (id: string) =>
  rest<Ticket>(`/tickets/${encodeURIComponent(id)}/close`, { method: "POST" });

export const fetchTickets = () =>
  rest<{ tickets: (Ticket & { pathId: string })[] | null; persistent: boolean; dispatches: boolean }>(
    "/tickets",
  ).then((b) => ({ tickets: b.tickets ?? [], persistent: b.persistent, dispatches: b.dispatches }));

// ── Red-team / BAS validation (REST) ────────────────────────────────

export interface ValidationInput {
  pathId?: string; // omitted for outcome=missed
  outcome: ValidationOutcome;
  source: string;
  evidence?: string;
  route?: string;
}

export const createValidation = (input: ValidationInput) =>
  rest<Validation & { id: string }>("/validations", { method: "POST", body: JSON.stringify(input) });

export const fetchValidations = () =>
  rest<{ validations: (Validation & { id: string; pathId?: string })[] | null; metrics: ValidationMetrics; persistent: boolean }>(
    "/validations",
  ).then((b) => ({ validations: b.validations ?? [], metrics: b.metrics, persistent: b.persistent }));
