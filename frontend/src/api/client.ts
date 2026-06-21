// Minimal GraphQL client for the AegisGraph BFF. In dev, requests to /graphql
// are proxied to the Go backend by Vite (see vite.config.ts).

const ENDPOINT = "/graphql";

export interface Node {
  id: string;
  label: string;
  name: string;
  internetExposed: boolean;
  crownJewel: boolean;
  runtimeAlert: boolean;
  severity?: string | null;
  cvss?: number | null;
}

export interface Edge {
  type: string;
  from: string;
  to: string;
  probability: number;
}

export interface Step {
  edgeType: string;
  from: string;
  to: string;
  probability: number;
}

export interface AttackPath {
  id: string;
  score: number;
  runtimeConfirmed: boolean;
  nodes: Node[];
  steps: Step[];
}

export interface Posture {
  criticalPaths: number;
  runtimeConfirmed: number;
  policyViolations: number;
  nodes: number;
  edges: number;
}

export interface Violation {
  invariantId: string;
  description: string;
  severity: string;
  nodes: Node[];
}

export interface Dashboard {
  posture: Posture;
  attackPaths: AttackPath[];
  invariantViolations: Violation[];
  graph: { nodes: Node[]; edges: Edge[] };
}

const NODE_FIELDS = `id label name internetExposed crownJewel runtimeAlert severity cvss`;

const DASHBOARD_QUERY = `
  query Dashboard {
    posture { criticalPaths runtimeConfirmed policyViolations nodes edges }
    attackPaths {
      id
      score
      runtimeConfirmed
      nodes { ${NODE_FIELDS} }
      steps { edgeType from to probability }
    }
    invariantViolations {
      invariantId
      description
      severity
      nodes { ${NODE_FIELDS} }
    }
    graph {
      nodes { ${NODE_FIELDS} }
      edges { type from to probability }
    }
  }
`;

async function gql<T>(query: string): Promise<T> {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) throw new Error(`GraphQL HTTP ${res.status}`);
  const body = await res.json();
  if (body.errors?.length) throw new Error(body.errors[0].message);
  return body.data as T;
}

export const fetchDashboard = () => gql<Dashboard>(DASHBOARD_QUERY);
