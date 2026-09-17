import type { ReactNode } from "react";
import { Logo } from "./icons";

// The dashboard has three destinations, not seven (four with the AI assistant). The old nav
// mirrored the engine's modules (overview / paths / plan / graph / violations / search),
// which made the reader assemble the story themselves. These follow the actual job: decide
// what to do, inspect the evidence, judge whether to trust it.
//
//   today - the decision surface: what is being exploited, what to fix, what moved
//   paths - the evidence: every route, searchable and inspectable
//   trust - the differentiator: calibration, validation, how honest the scores are
//
// They are tabs, not a sidebar. A 224px column held three entries and cost the attack-path
// list the width it needed to show a route's name, and on a phone it hid all three behind a
// hamburger. Desktop gets a top bar; a phone gets a tab bar at the bottom, where a thumb is.
export type View = "today" | "paths" | "trust" | "assistant";

type IconProps = { className?: string };

const stroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round",
  strokeLinejoin: "round",
} as const;

function TodayIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" {...stroke}>
      <path d="M3 10.5 L7 10.5 L9 5.5 L11.5 14.5 L13.5 10.5 L17 10.5" />
    </svg>
  );
}

function PathsIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" {...stroke}>
      <circle cx="4.5" cy="15.5" r="1.8" />
      <circle cx="15.5" cy="4.5" r="1.8" />
      <path d="M6 14.2 C 10 11, 10 9, 14.2 5.8" />
    </svg>
  );
}

function TrustIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" {...stroke}>
      <path d="M10 2.5 L16.5 5 V10 C16.5 14 13.5 16.5 10 17.5 C6.5 16.5 3.5 14 3.5 10 V5 Z" />
      <path d="M7.2 10 L9.2 12 L13 8" />
    </svg>
  );
}

function AssistantIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" {...stroke}>
      <path d="M9 2.5 L10.2 6 L13.5 7.2 L10.2 8.4 L9 12 L7.8 8.4 L4.5 7.2 L7.8 6 Z" />
      <path d="M14.5 11.5 L15.2 13.3 L17 14 L15.2 14.7 L14.5 16.5 L13.8 14.7 L12 14 L13.8 13.3 Z" />
    </svg>
  );
}

function SearchIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" {...stroke}>
      <circle cx="9" cy="9" r="5.5" />
      <path d="M13.5 13.5 L17 17" />
    </svg>
  );
}

interface Item {
  view: View;
  label: string;
  // The phone tab bar has a quarter of 375px per entry; the desktop label does not fit.
  short: string;
  Icon: (p: IconProps) => ReactNode;
  count?: number;
}

function sections(pathCount: number, aiEnabled: boolean): Item[] {
  return [
    { view: "today", label: "Today", short: "Today", Icon: TodayIcon },
    { view: "paths", label: "Attack paths", short: "Paths", Icon: PathsIcon, count: pathCount },
    { view: "trust", label: "Trust", short: "Trust", Icon: TrustIcon },
    ...(aiEnabled ? [{ view: "assistant" as const, label: "AI assistant", short: "Assistant", Icon: AssistantIcon }] : []),
  ];
}

// "analyzed 12s ago" - a coarse relative time so a tester can see the data is fresh (and
// how stale it is if the analyzer stalls).
function ago(iso?: string | null): string | null {
  if (!iso) return null;
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (!Number.isFinite(secs)) return null;
  if (secs < 60) return `analyzed ${secs}s ago`;
  if (secs < 3600) return `analyzed ${Math.floor(secs / 60)}m ago`;
  return `analyzed ${Math.floor(secs / 3600)}h ago`;
}

interface TopBarProps {
  view: View;
  onNavigate: (v: View) => void;
  pathCount: number;
  aiEnabled?: boolean;
  live: boolean;
  analyzedAt?: string | null;
  // Staleness pruning totals (omitted/zero when GRAPH_TTL pruning is off).
  pruned?: { nodes: number; edges: number } | null;
  // Opens the command palette; absent when full-text search is off.
  onOpenSearch?: () => void;
  // Scope, export, appearance and session - the page decides what it offers.
  children?: ReactNode;
}

export function TopBar({
  view,
  onNavigate,
  pathCount,
  aiEnabled = false,
  live,
  analyzedAt,
  pruned,
  onOpenSearch,
  children,
}: TopBarProps) {
  const analyzed = live ? ago(analyzedAt) : null;
  const prunedTotal = pruned ? pruned.nodes + pruned.edges : 0;
  const status = live
    ? [analyzed ?? "live", prunedTotal > 0 ? `pruned ${prunedTotal} stale` : null].filter(Boolean).join(" · ")
    : "backend unreachable";

  return (
    <header className="shrink-0 border-b border-edge bg-ink">
      <div className="flex h-14 items-center gap-3 px-4 sm:px-8 md:gap-6">
        <button
          type="button"
          onClick={() => onNavigate("today")}
          className="flex shrink-0 items-center gap-2.5"
          aria-label="PerspectiveGraph - go to Today"
        >
          <Logo className="h-7 w-7" />
          <span className="hidden text-[15px] font-semibold tracking-tight text-slate-900 lg:inline">
            PerspectiveGraph
          </span>
        </button>

        <nav aria-label="Sections" className="hidden h-14 items-stretch gap-1 md:flex">
          {sections(pathCount, aiEnabled).map(({ view: v, label, short, count }) => {
            const active = view === v;
            return (
              // Short labels below lg. On a tablet, signed in with the assistant enabled, the
              // full labels wrapped onto two lines and squeezed the scope select down to its
              // arrow. The accessible name is always the full label.
              <button
                key={v}
                type="button"
                onClick={() => onNavigate(v)}
                aria-current={active ? "page" : undefined}
                aria-label={count ? `${label}, ${count}` : label}
                className={`-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 text-[14px] font-medium transition ${
                  active
                    ? "border-accent text-slate-900"
                    : "border-transparent text-slate-500 hover:text-slate-800"
                }`}
              >
                <span className="lg:hidden">{short}</span>
                <span className="hidden lg:inline">{label}</span>
                {count !== undefined && count > 0 && (
                  <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[12px] font-semibold tabular-nums text-slate-700">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="ml-auto flex min-w-0 items-center gap-2">
          {/* Freshness, next to the data it describes. A dot alone below xl, with the
              full sentence in its tooltip, so a narrow bar keeps room for the controls. */}
          <span className="flex shrink-0 items-center gap-2 text-[12px] text-muted" title={status} role="status">
            <span className="relative flex h-2 w-2">
              {live && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
              )}
              <span className={`relative inline-flex h-2 w-2 rounded-full ${live ? "bg-emerald-400" : "bg-amber-400"}`} />
            </span>
            <span className="hidden xl:inline">{status}</span>
          </span>
          {onOpenSearch && (
            // Search is a verb, not a place: it belongs next to whatever you are already
            // looking at, and on the keyboard.
            <button
              type="button"
              onClick={onOpenSearch}
              aria-label="Search assets"
              title="Search assets (⌘K)"
              className="flex h-9 shrink-0 items-center gap-2 rounded-lg border border-edge bg-panel px-2.5 text-[13px] text-slate-500 shadow-card transition hover:border-accent/50 hover:text-slate-700"
            >
              <SearchIcon className="h-4 w-4" />
              <span className="hidden lg:inline">Search</span>
              <kbd className="hidden rounded border border-edge px-1.5 text-[12px] tabular-nums text-slate-400 lg:inline">⌘K</kbd>
            </button>
          )}
          {children}
        </div>
      </div>
    </header>
  );
}

interface BottomBarProps {
  view: View;
  onNavigate: (v: View) => void;
  pathCount: number;
  aiEnabled?: boolean;
}

// The phone's navigation. Fixed to the bottom and sized for a thumb: each entry is a
// full-height column, well over the 44px a touch target needs.
export function BottomBar({ view, onNavigate, pathCount, aiEnabled = false }: BottomBarProps) {
  const items = sections(pathCount, aiEnabled);
  return (
    <nav
      aria-label="Sections"
      className="fixed inset-x-0 bottom-0 z-30 grid border-t border-edge bg-panel pb-[env(safe-area-inset-bottom)] md:hidden"
      style={{ gridTemplateColumns: `repeat(${items.length}, minmax(0, 1fr))` }}
    >
      {items.map(({ view: v, short, Icon, count }) => {
        const active = view === v;
        return (
          <button
            key={v}
            type="button"
            onClick={() => onNavigate(v)}
            aria-current={active ? "page" : undefined}
            className={`relative flex h-16 flex-col items-center justify-center gap-1 text-[12px] font-medium transition ${
              active ? "text-accent" : "text-slate-500"
            }`}
          >
            <Icon className="h-5 w-5" />
            {short}
            {count !== undefined && count > 0 && (
              <span className="absolute left-1/2 top-2 ml-2 rounded-full bg-slate-700 px-1.5 text-[12px] font-semibold leading-4 tabular-nums text-panel">
                {count}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
