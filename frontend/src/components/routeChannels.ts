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

export type RouteStatus = "new" | "triaged" | "fixing" | "proven" | "refuted";

export const STATUS_META: Record<RouteStatus, { label: string; className: string; hint: string }> = {
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
  // Proven is the only filled pill on the board. It earns that by form rather than by a
  // new hue: colour here means lifecycle, and "somebody walked this end to end" is the
  // strongest claim any row can carry.
  proven: {
    label: "Proven",
    className: "bg-slate-900 text-panel px-1.5 py-[1px] rounded",
    hint: "A red-team or BAS run walked this route end to end. Not a model estimate - it was done.",
  },
  refuted: {
    label: "Refuted",
    className: "text-status-verified",
    hint: "A tester tried this route and it did not work. The engine was wrong; suppress it as a false positive.",
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
  if (outcome === "refuted") return "refuted";
  if (path.ticket) return "fixing";
  if (path.suppressed || path.suppression) return "triaged";
  return "new";
}

// Who recorded the verdict, for the briefing to say whether live traffic on a route is
// an intruder or your own exercise.
export function verdictSource(path: AttackPath): string | undefined {
  return path.validation?.source || undefined;
}

// Order for display: a route a tester DISPROVED sinks to the bottom.
//
// The engine ranks by composite priority, which knows nothing about verdicts - so a
// route the red team walked and could not exploit kept its score and sat second on the
// home page, in one of the three slots the product spends its credibility on. The
// trust page counted the same route among the refuted. Two screens, opposite advice.
//
// Sunk rather than hidden: "the engine was wrong here" is information, and a reader
// scrolling the full list should still meet it - with its Refuted pill on - rather than
// wonder where it went. Everything else keeps the engine's own order, so this changes
// exactly one thing.
export function orderForDisplay(paths: AttackPath[]): AttackPath[] {
  return [...paths].sort((a, b) => Number(routeStatus(a) === "refuted") - Number(routeStatus(b) === "refuted"));
}
