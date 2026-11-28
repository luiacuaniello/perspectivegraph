import type { View } from "./components/Navigation";

// The URL hash names a view, and on the paths view it can also name one route:
// #paths/<path id>. A route that could not be linked could not be pasted into a ticket or
// a chat, and "open the dashboard and find the third route to payments-admin" is not a
// link anyone follows.
//
// Path ids are stable: the engine derives them from the route itself, so the same route
// keeps its id across analyses and restarts, and a link stays good for as long as the
// route stays open.
//
// The verdict page names a commit instead: #verdict/<owner>/<repo>/<sha>, the link a
// merge-gate commit status carries. A GitLab project path has more segments than two;
// the SHA is always the last.

export const VIEWS: View[] = ["today", "paths", "accuracy", "assistant", "verdict"];

// The old hashes still resolve so existing links and bookmarks don't break.
const LEGACY_VIEWS: Record<string, View> = {
  overview: "today",
  plan: "today",
  violations: "today",
  graph: "paths",
  search: "paths",
  trust: "accuracy",
};

// A commit, as the merge gate names one.
export interface CommitRef {
  slug: string;
  sha: string;
}

export interface HashRoute {
  view: View;
  // The route the link names, or null when it names only a view.
  pathId: string | null;
  // On the verdict page: the commit the link names, or null for the lookup form.
  commit?: CommitRef | null;
}

// What a repository segment and a SHA may hold. The link arrives from outside, and a
// commit that cannot exist is better refused here than asked of the engine.
const SLUG_PART = /^[A-Za-z0-9._-]+$/;
const SHA = /^[0-9a-fA-F]{7,64}$/;

export function validSlug(slug: string): boolean {
  const parts = slug.split("/");
  return parts.length >= 2 && parts.every((p) => SLUG_PART.test(p) && p !== "." && p !== "..");
}

export function validSha(sha: string): boolean {
  return SHA.test(sha);
}

function decode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    // A hand-edited link with a stray '%' still names something; keep it as typed.
    return segment;
  }
}

function parseCommit(rest: string): CommitRef | null {
  const parts = rest.split("/").filter(Boolean).map(decode);
  if (parts.length < 3) return null;
  const sha = parts[parts.length - 1];
  const slug = parts.slice(0, -1).join("/");
  return validSlug(slug) && validSha(sha) ? { slug, sha } : null;
}

export function parseHash(hash: string): HashRoute {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const slash = raw.indexOf("/");
  const head = slash < 0 ? raw : raw.slice(0, slash);
  const view = VIEWS.includes(head as View) ? (head as View) : (LEGACY_VIEWS[head] ?? "today");
  if (view === "verdict") {
    return { view, pathId: null, commit: slash < 0 ? null : parseCommit(raw.slice(slash + 1)) };
  }
  // Only the paths view has routes to name; anything after a slash elsewhere is ignored
  // rather than carried into a view that would not know what to do with it.
  if (view !== "paths" || slash < 0) return { view, pathId: null };
  return { view, pathId: decode(raw.slice(slash + 1)) || null };
}

export function hashFor(view: View, pathId?: string | null, commit?: CommitRef | null): string {
  if (view === "verdict" && commit) {
    return `verdict/${commit.slug.split("/").map(encodeURIComponent).join("/")}/${encodeURIComponent(commit.sha)}`;
  }
  return view === "paths" && pathId ? `paths/${encodeURIComponent(pathId)}` : view;
}

// The absolute link to one route, for sharing.
export function linkToPath(pathId: string, loc: Pick<Location, "origin" | "pathname" | "search"> = window.location): string {
  return `${loc.origin}${loc.pathname}${loc.search}#${hashFor("paths", pathId)}`;
}
