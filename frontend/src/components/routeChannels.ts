import type { AttackPath } from "../api/client";

// Three separate visual channels, one fact each.
//
// Before this, colour carried three different meanings at once: amber was a crown jewel
// AND a P2 band AND a policy warning; red was "actively exploited" AND a high score AND a
// runtime flag. Nothing could be read at a glance because no channel was reliable.
//
//   colour  → where the route is in its lifecycle (new / triaged / fixing / verified)
//   bar+num → how urgent it is (priority), never colour
//   icon    → what kind of asset it reaches
//
// Severity deliberately leaves the colour channel. It is a bar and a number, so the page
// still ranks correctly for someone who cannot separate a red from a green - and so that
// colour is free to say the thing colour is actually good at: state.

export type RouteStatus = "new" | "triaged" | "fixing" | "proven" | "refuted" | "conflict";

export const STATUS_META: Record<RouteStatus, { label: string; className: string; hint: string; glyph?: string }> = {
  new: {
    label: "New",
    className: "text-status-new",
    hint: "Nobody has looked at this route yet.",
  },
  triaged: {
    label: "Triaged",
    className: "text-status-triaged",
    hint: "A decision was recorded: accepted, false positive, mitigated or duplicate.",
  },
  fixing: {
    label: "Fixing",
    className: "text-status-fixing",
    hint: "A remediation ticket is open for this route.",
  },
  // Proven and Refuted were ONE state called "Verified", which was wrong in the way that
  // matters: it showed the same green pill whether a tester had confirmed the route was
  // exploitable or proven it was not. Those demand opposite actions - fix it, or suppress
  // it as a false positive - and the green read as "checked, fine" for both.
  //
  // Proven was the only filled pill on the board, and a solid block outweighed the name of
  // the asset beside it - the one thing the row is about. It keeps the strongest text and a
  // check mark instead of the dot, which is enough to find it without shouting.
  proven: {
    label: "Proven",
    className: "text-slate-800",
    hint: "A red-team or BAS run walked this route end to end. Not a model estimate - it was done.",
    glyph: "✓",
  },
  // Neutral, not green. Green reads as "defended", and a refuted route is not defended - a
  // tester failed to walk it, which is evidence against the engine's claim, no more.
  refuted: {
    label: "Refuted",
    className: "text-slate-500",
    hint: "A tester tried this route and it did not work. The engine was wrong; suppress it as a false positive.",
  },
  // A refuted route with a runtime alert on it, or to an asset open to anyone. The green
  // of Refuted would tell the reader to suppress the one route whose evidence says it is
  // live. Outlined rather than a new hue, like Proven: red stays reserved for runtime.
  conflict: {
    label: "Evidence conflicts",
    className: "border border-current text-slate-800 px-1.5 rounded",
    hint: "A tester could not walk this route, but a runtime alert fired on it or the asset is open to anyone. A failed test does not undo that - find out which is wrong before suppressing it.",
  },
};

// The engine already knows all of these - it opens tickets, records suppressions and
// stores validation verdicts. The UI simply never showed them as a state, so the same
// route looked identical whether it had been triaged an hour ago or never touched.
//
// The verdict outcome is read, not just its existence: "partial" counts as proven,
// because a route an attacker got part way along is a route that works well enough to
// matter, and treating it as unproven would be the flattering reading.
export function routeStatus(path: AttackPath): RouteStatus {
  const outcome = path.validation?.outcome;
  if (outcome === "confirmed" || outcome === "partial") return "proven";
  if (outcome === "refuted") return path.runtimeConfirmed || path.directAccess ? "conflict" : "refuted";
  if (path.ticket) return "fixing";
  if (path.suppressed || path.suppression) return "triaged";
  return "new";
}

// The list's shape: one group per sensitive asset, in the engine's order, and the routes a
// tester disproved set apart.
//
// Grouped because the same asset keeps coming back: cluster-admin reached four ways read as
// four unrelated rows, when the question is "what do I stand to lose, and by how many
// routes". A group sits where its most urgent route sits - the order is still the engine's,
// read one asset at a time.
//
// Refuted routes leave the groups. They were already at the bottom (the engine drops them to
// P3), but mixed in with routes nobody has tested they looked like work still to do. A
// refuted route with a runtime alert on it is not here: that is a conflict, and it stays
// where the alert puts it.
export interface TargetGroup {
  key: string;
  target: AttackPath["nodes"][number] | undefined;
  routes: AttackPath[];
}

export function groupByTarget(paths: AttackPath[]): { groups: TargetGroup[]; refuted: AttackPath[] } {
  const groups: TargetGroup[] = [];
  const byKey = new Map<string, TargetGroup>();
  const refuted: AttackPath[] = [];
  for (const p of paths) {
    if (routeStatus(p) === "refuted") {
      refuted.push(p);
      continue;
    }
    const target = p.nodes[p.nodes.length - 1];
    const key = target?.id ?? p.id;
    let g = byKey.get(key);
    if (!g) {
      g = { key, target, routes: [] };
      byKey.set(key, g);
      groups.push(g);
    }
    g.routes.push(p);
  }
  return { groups, refuted };
}

// Who recorded the verdict, for the briefing to say whether live traffic on a route is
// an intruder or your own exercise.
export function verdictSource(path: AttackPath): string | undefined {
  return path.validation?.source || undefined;
}

// routeLabel names a route in one line: "entry → target", or, for a sensitive asset
// open to anyone - a direct-access path, the asset alone - the asset and why, since
// "customer-exports → customer-exports" reads as a route from itself.
export function routeLabel(path: AttackPath): string {
  const to = path.nodes[path.nodes.length - 1]?.name ?? "?";
  if (path.directAccess) return `${to} (open to anyone)`;
  return `${path.nodes[0]?.name ?? "?"} → ${to}`;
}
