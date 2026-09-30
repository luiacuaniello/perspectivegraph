import type { View } from "./components/Navigation";

// The URL hash names a view, and on the paths view it can also name one route:
// #paths/<path id>. A route that could not be linked could not be pasted into a ticket or
// a chat, and "open the dashboard and find the third route to payments-admin" is not a
// link anyone follows.
//
// Path ids are stable: the engine derives them from the route itself, so the same route
// keeps its id across analyses and restarts, and a link stays good for as long as the
// route stays open.

export const VIEWS: View[] = ["today", "paths", "accuracy", "assistant"];

// The old hashes still resolve so existing links and bookmarks don't break.
const LEGACY_VIEWS: Record<string, View> = {
  overview: "today",
  plan: "today",
  violations: "today",
  graph: "paths",
  search: "paths",
  trust: "accuracy",
};

export interface HashRoute {
  view: View;
  // The route the link names, or null when it names only a view.
  pathId: string | null;
}

export function parseHash(hash: string): HashRoute {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const slash = raw.indexOf("/");
  const head = slash < 0 ? raw : raw.slice(0, slash);
  const view = VIEWS.includes(head as View) ? (head as View) : (LEGACY_VIEWS[head] ?? "today");
  // Only the paths view has routes to name; anything after a slash elsewhere is ignored
  // rather than carried into a view that would not know what to do with it.
  if (view !== "paths" || slash < 0) return { view, pathId: null };
  let id = raw.slice(slash + 1);
  try {
    id = decodeURIComponent(id);
  } catch {
    // A hand-edited link with a stray '%' still names something; keep it as typed.
  }
  return { view, pathId: id || null };
}

export function hashFor(view: View, pathId?: string | null): string {
  return view === "paths" && pathId ? `paths/${encodeURIComponent(pathId)}` : view;
}

// The absolute link to one route, for sharing.
export function linkToPath(pathId: string, loc: Pick<Location, "origin" | "pathname" | "search"> = window.location): string {
  return `${loc.origin}${loc.pathname}${loc.search}#${hashFor("paths", pathId)}`;
}
