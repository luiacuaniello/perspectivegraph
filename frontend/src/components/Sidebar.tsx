import type { ReactElement } from "react";
import { Logo, XIcon } from "./icons";

// The dashboard has three destinations, not seven. The old nav mirrored the
// engine's modules (overview / paths / plan / graph / violations / search), which
// made the reader assemble the story themselves. These three follow the actual
// job: decide what to do, inspect the evidence, judge whether to trust it.
//
//   today - the decision surface: what is being exploited, what to fix, what moved
//   paths - the evidence: every route, searchable and inspectable
//   trust - the differentiator: calibration, validation, how honest the scores are
//
// Remediation and violations fold into `today` as the actions and signals they
// are; the graph is reached from a path (where it has context) rather than as a
// destination; search is the command palette.
export type View = "today" | "paths" | "trust" | "assistant";

interface Item {
  view: View;
  label: string;
  icon: ReactElement;
  badge?: number;
  badgeTone?: "danger" | "warn";
}

interface Props {
  view: View;
  onNavigate: (v: View) => void;
  pathCount: number;
  // Opens the command palette (search is no longer a destination).
  onOpenSearch?: () => void;
  live: boolean;
  analyzedAt?: string | null;
  // Staleness pruning totals (omitted/zero when GRAPH_TTL pruning is off).
  pruned?: { nodes: number; edges: number } | null;
  // Mobile drawer state (ignored on desktop, where the sidebar is always shown).
  open?: boolean;
  onClose?: () => void;
  // Show the AI assistant entry only when the backend has ANTHROPIC_API_KEY set.
  aiEnabled?: boolean;
  // Show the GraphQL playground link only when the API is open: GraphiQL can't
  // carry a bearer token, so on an auth-secured API it would just 401.
  showPlayground?: boolean;
}

// "analyzed 12s ago" - a coarse relative time so a tester can see the data is
// fresh (and how stale it is if the analyzer stalls).
function ago(iso?: string | null): string | null {
  if (!iso) return null;
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (!Number.isFinite(secs)) return null;
  if (secs < 60) return `analyzed ${secs}s ago`;
  if (secs < 3600) return `analyzed ${Math.floor(secs / 60)}m ago`;
  return `analyzed ${Math.floor(secs / 3600)}h ago`;
}

const stroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round",
  strokeLinejoin: "round",
} as const;

const icons = {
  today: (
    <svg viewBox="0 0 20 20" className="h-4 w-4" {...stroke}>
      <path d="M3 10.5 L7 10.5 L9 5.5 L11.5 14.5 L13.5 10.5 L17 10.5" />
    </svg>
  ),
  trust: (
    <svg viewBox="0 0 20 20" className="h-4 w-4" {...stroke}>
      <path d="M10 2.5 L16.5 5 V10 C16.5 14 13.5 16.5 10 17.5 C6.5 16.5 3.5 14 3.5 10 V5 Z" />
      <path d="M7.2 10 L9.2 12 L13 8" />
    </svg>
  ),
  paths: (
    <svg viewBox="0 0 20 20" className="h-4 w-4" {...stroke}>
      <circle cx="4.5" cy="15.5" r="1.8" />
      <circle cx="15.5" cy="4.5" r="1.8" />
      <path d="M6 14.2 C 10 11, 10 9, 14.2 5.8" />
    </svg>
  ),
  search: (
    <svg viewBox="0 0 20 20" className="h-4 w-4" {...stroke}>
      <circle cx="9" cy="9" r="5.5" />
      <path d="M13.5 13.5 L17 17" />
    </svg>
  ),
  assistant: (
    <svg viewBox="0 0 20 20" className="h-4 w-4" {...stroke}>
      <path d="M9 2.5 L10.2 6 L13.5 7.2 L10.2 8.4 L9 12 L7.8 8.4 L4.5 7.2 L7.8 6 Z" />
      <path d="M14.5 11.5 L15.2 13.3 L17 14 L15.2 14.7 L14.5 16.5 L13.8 14.7 L12 14 L13.8 13.3 Z" />
    </svg>
  ),
};

export default function Sidebar({
  view,
  onNavigate,
  pathCount,
  onOpenSearch,
  live,
  analyzedAt,
  pruned,
  open = false,
  onClose,
  aiEnabled = false,
  showPlayground = true,
}: Props) {
  const items: Item[] = [
    { view: "today", label: "Today", icon: icons.today },
    { view: "paths", label: "Attack paths", icon: icons.paths, badge: pathCount, badgeTone: "danger" },
    { view: "trust", label: "Trust", icon: icons.trust },
    ...(aiEnabled ? [{ view: "assistant" as const, label: "AI assistant", icon: icons.assistant }] : []),
  ];

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 flex w-56 shrink-0 flex-col border-r border-edge bg-panel shadow-xl transition-transform duration-200 lg:static lg:z-auto lg:shadow-none lg:transition-none ${
        open ? "translate-x-0" : "-translate-x-full"
      } lg:translate-x-0`}
    >
      <div className="flex items-center gap-2.5 px-5 pb-5 pt-6">
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-panel-2 ring-1 ring-edge">
          <Logo className="h-7 w-7" />
        </span>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight text-slate-900">PerspectiveGraph</div>
          <div className="text-[10px] text-muted">Attack-path engine</div>
        </div>
        <button
          onClick={onClose}
          aria-label="Close menu"
          className="ml-auto grid h-7 w-7 place-items-center rounded-md text-slate-400 transition hover:bg-slate-100 hover:text-slate-600 lg:hidden"
        >
          <XIcon className="h-4 w-4" />
        </button>
      </div>

      <nav className="flex flex-col gap-1 px-3">
        {items.map((it) => {
          const active = view === it.view;
          return (
            <button
              key={it.view}
              onClick={() => {
                onNavigate(it.view);
                onClose?.();
              }}
              className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] font-medium transition ${
                active
                  ? "bg-accent-soft text-accent shadow-[inset_2px_0_0_0_var(--color-accent)]"
                  : "text-slate-500 hover:bg-slate-100 hover:text-slate-700"
              }`}
            >
              <span className={active ? "text-accent" : "text-slate-500 group-hover:text-slate-600"}>
                {it.icon}
              </span>
              <span className="flex-1 text-left">{it.label}</span>
              {it.badge !== undefined && it.badge > 0 && (
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold tabular-nums ${
                    it.badgeTone === "warn"
                      ? "bg-amber-500/15 text-amber-700"
                      : "bg-red-500/15 text-red-700"
                  }`}
                >
                  {it.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {onOpenSearch && (
        // Search is a verb, not a place: it belongs on the keyboard, next to
        // whatever you are already looking at, rather than as a destination you
        // navigate away to.
        <div className="px-3 pt-3">
          <button
            onClick={() => {
              onOpenSearch();
              onClose?.();
            }}
            className="flex w-full items-center gap-2.5 rounded-lg border border-edge px-3 py-2 text-[12px] text-slate-500 transition hover:border-accent/50 hover:text-slate-700"
          >
            <span className="text-slate-400">{icons.search}</span>
            <span className="flex-1 text-left">Search assets</span>
            <kbd className="rounded border border-edge px-1.5 py-0.5 text-[10px] tabular-nums text-slate-400">⌘K</kbd>
          </button>
        </div>
      )}

      <div className="mt-auto px-5 pb-5">
        {showPlayground && (
          // Relative path: served through the dashboard's own origin (nginx proxies
          // /graphql to the backend), so it works on any host - not just localhost.
          <a
            href="/graphql"
            target="_blank"
            rel="noreferrer"
            className="text-[11px] text-slate-500 underline-offset-2 hover:text-slate-600 hover:underline"
          >
            GraphQL playground ↗
          </a>
        )}
        <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-500">
          <span className={`relative flex h-2 w-2 ${live ? "" : "opacity-80"}`}>
            {live && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
            )}
            <span
              className={`relative inline-flex h-2 w-2 rounded-full ${live ? "bg-emerald-400" : "bg-amber-400"}`}
            />
          </span>
          {live ? "live · refresh 5s" : "backend unreachable"}
        </div>
        {live && ago(analyzedAt) && (
          <div className="mt-1 text-[10px] text-slate-400">{ago(analyzedAt)}</div>
        )}
        {live && pruned && pruned.nodes + pruned.edges > 0 && (
          <div
            className="mt-0.5 text-[10px] text-slate-400"
            title="Stale assets removed by the TTL pruner (assets that left the source feeds), so they can't generate phantom attack paths."
          >
            pruned {pruned.nodes + pruned.edges} stale
          </div>
        )}
      </div>
    </aside>
  );
}
