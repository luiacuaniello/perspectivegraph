// Plain language for attack paths: the words a reader needs in place of the engine's own.
import type { AttackPath, Node, Step } from "../api/client";

// The kill chain used to print the ontology: EXPOSES, HOSTS, DEPENDS_ON, IAM_Role. Those
// are the engine's words. A reader needs the verb between two assets and, where the jump is
// not obvious, why it holds.

const TYPE_NAMES: Record<string, string> = {
  IAM_Role: "IAM role",
  IAM_User: "IAM user",
  IAM_Policy: "IAM policy",
  LoadBalancer: "Load balancer",
  IdentityProvider: "Identity provider",
  ServiceAccount: "Service account",
  SecurityGroup: "Security group",
  VirtualMachine: "Virtual machine",
  CVE: "Vulnerability (CVE)",
  K8sRole: "Kubernetes role",
};

export function typeName(label: string): string {
  if (TYPE_NAMES[label]) return TYPE_NAMES[label];
  const words = label.replace(/_/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2");
  return words.charAt(0).toUpperCase() + words.slice(1).toLowerCase();
}

// HOP_VERB is what one asset does to the next, read top to bottom.
const HOP_VERB: Record<string, string> = {
  EXPOSES: "exposes",
  ROUTES_TO: "routes traffic to",
  HOSTS: "runs",
  DEPENDS_ON: "ships",
  AFFECTS: "is vulnerable to",
  EXPLOITS: "exploited, gives access to",
  CONNECTS_TO: "can reach over the network",
  ASSUMES: "can assume",
  HAS_PERMISSION: "has permissions on",
  CAN_ESCALATE_TO: "can escalate to",
  AUTHENTICATES: "signs in",
  ESCAPES_TO: "can break out to",
  BUILT_FROM: "is built from",
  COMPILED_INTO: "is compiled into",
};

export function hopVerb(edgeType: string): string {
  return HOP_VERB[edgeType] ?? edgeType.toLowerCase().replace(/_/g, " ");
}

// bareName drops the qualifier the engine appends to a name - "payments-admin
// (AdministratorAccess)" - where a sentence needs the thing itself: a possessive read
// "payments-admin (AdministratorAccess)'s credentials".
export function bareName(name: string): string {
  return name.replace(/\s*\(.*\)\s*$/, "");
}

// hopReason explains the hops a reader would otherwise have to take on faith.
export function hopReason(step: Step, from?: Node, to?: Node): string | null {
  switch (step.edgeType) {
    case "EXPOSES":
    case "ROUTES_TO":
      return from?.internetExposed ? "reachable from the internet" : null;
    case "EXPLOITS": {
      const target = to ? typeName(to.label).toLowerCase() : "";
      if (/role|user|account|identity|principal/.test(target)) {
        return `code execution in the workload lets the attacker act with ${bareName(to!.name)}'s credentials`;
      }
      return "code execution in the workload lets the attacker reach it";
    }
    case "CAN_ESCALATE_TO":
      return "IAM privilege escalation: it can grant itself more (PassRole, policy attachment, a new policy version)";
    case "ESCAPES_TO":
      return "a privileged or host-mounted container";
    case "ASSUMES":
      return from?.internetExposed ? "its trust policy admits principals from outside" : null;
    default:
      return null;
  }
}

// pathSummary is the route in one sentence: where it starts, what it reaches, and the one
// weakness that makes it work.
export function pathSummary(path: AttackPath): string {
  const entry = path.nodes[0];
  const target = path.nodes[path.nodes.length - 1];
  if (!entry || !target) return "";
  if (path.directAccess) return `${target.name} is open to anyone: there is nothing to exploit.`;
  const nameOf = (id: string) => bareName(path.nodes.find((n) => n.id === id)?.name ?? id);
  const n = path.steps.length;
  const from = entry.internetExposed ? `From the internet, through ${entry.name}` : `From ${entry.name}`;
  const cve = path.nodes.find((x) => x.label === "CVE");
  const step = (t: string) => path.steps.find((s) => s.edgeType === t);
  let how = "";
  if (cve) how = `, by exploiting ${cve.name}${cve.kev ? " (known exploited)" : ""}`;
  else if (step("CAN_ESCALATE_TO")) how = `, by escalating ${nameOf(step("CAN_ESCALATE_TO")!.from)}'s privileges`;
  else if (step("ESCAPES_TO")) how = `, by breaking out of ${nameOf(step("ESCAPES_TO")!.from)}`;
  else if (step("AUTHENTICATES")) how = `, by signing in as ${nameOf(step("AUTHENTICATES")!.to)}`;
  return `${from}, an attacker reaches ${target.name} in ${n} step${n === 1 ? "" : "s"}${how}.`;
}
