import type { AttackPath } from "../api/client";
import { category, CATEGORY_STYLE } from "./graphColors";
import { STATUS_META, type RouteStatus } from "./routeChannels";

// The three channels as components. The logic and the constants live in
// routeChannels.ts next door - split so the module exports only components, which is
// what keeps fast refresh working (the same reason graphColors.ts is its own file).

export function StatusPill({ status }: { status: RouteStatus }) {
  const meta = STATUS_META[status];
  // "Proven" is the one filled pill, so it drops the dot: the fill is already the mark,
  // and a dot inside a solid block reads as a smudge rather than a signal.
  const filled = status === "proven";
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 text-[10.5px] font-medium ${meta.className}`}
      title={meta.hint}
    >
      {!filled && <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />}
      {meta.label}
    </span>
  );
}

// Severity as shape, not hue: a track whose fill length IS the number beside it, so the
// two encode the same fact twice and neither depends on colour.
export function SeverityBar({ priority, score }: { priority?: number | null; score: number }) {
  // Priority is what orders the list; the raw exploit score is the fallback for a path
  // the analyzer has not banded yet.
  const value = priority ?? score * 100;
  return (
    <span
      className="flex shrink-0 items-center gap-2"
      title={
        priority != null
          ? `Triage priority ${value.toFixed(0)}/100 - what ranks this list. Exploit score is ${Math.round(score * 100)}%.`
          : `Exploit score ${Math.round(score * 100)}%`
      }
    >
      <span className="h-1 w-10 overflow-hidden rounded-full bg-slate-200">
        <span
          className="block h-full bg-slate-600"
          style={{ width: `${Math.max(4, Math.min(100, value))}%` }}
        />
      </span>
      <span className="w-6 text-right text-[12px] font-semibold tabular-nums text-slate-800">
        {value.toFixed(0)}
      </span>
    </span>
  );
}

// What the route reaches, as a shape. Shapes survive projectors, colour-blindness and
// print - which is why the graph already encodes category this way; this reuses the same
// vocabulary so the list and the map teach each other.
export function TargetIcon({ path, className = "" }: { path: AttackPath; className?: string }) {
  const target = path.nodes[path.nodes.length - 1];
  const cat = category(target?.label ?? "");
  const style = CATEGORY_STYLE[cat];
  const common = { className: `h-3 w-3 shrink-0 ${className}`, viewBox: "0 0 12 12", "aria-hidden": true } as const;
  const fill = "currentColor";
  return (
    <span className="text-muted" title={`Reaches a ${style.name.toLowerCase()}`}>
      {cat === "data" ? (
        <svg {...common}>
          <ellipse cx="6" cy="3" rx="4" ry="1.6" fill={fill} />
          <path d="M2 3v6c0 .9 1.8 1.6 4 1.6s4-.7 4-1.6V3" fill="none" stroke={fill} strokeWidth="1.2" />
        </svg>
      ) : cat === "identity" ? (
        <svg {...common}>
          <circle cx="6" cy="4" r="2.3" fill={fill} />
          <path d="M1.6 11c.6-2.4 2.3-3.6 4.4-3.6S9.8 8.6 10.4 11" fill="none" stroke={fill} strokeWidth="1.2" />
        </svg>
      ) : cat === "code" ? (
        <svg {...common}>
          <path d="M6 1l4.3 2.5v5L6 11 1.7 8.5v-5z" fill="none" stroke={fill} strokeWidth="1.2" />
        </svg>
      ) : cat === "finding" ? (
        <svg {...common}>
          <path d="M6 1l5 9.5H1z" fill="none" stroke={fill} strokeWidth="1.2" />
          <path d="M6 4.6v2.6" stroke={fill} strokeWidth="1.2" strokeLinecap="round" />
        </svg>
      ) : (
        <svg {...common}>
          <rect x="1.4" y="2.4" width="9.2" height="7.2" rx="1.4" fill="none" stroke={fill} strokeWidth="1.2" />
        </svg>
      )}
    </span>
  );
}

// The two tokens that make a route a phone call rather than a ticket.
//
// `edge-alb (0.0.0.0/0) → payments-admin (AdministratorAccess)` is a load balancer open
// to the entire internet reaching a role with full admin. That sentence is worse than
// the priority number beside it, and both halves of it were rendered as ordinary text -
// the qualifier in particular read as a parenthetical aside, which is exactly what it is
// not.
//
// Weight, not colour: the palette's hues are already spoken for (lifecycle, and the one
// red that means "right now"), and this is emphasis, not a new category.
export function NodeName({ name, className = "" }: { name?: string; className?: string }) {
  if (!name) return <span className={className}>?</span>;
  const m = name.match(/^(.*?)\s*\(([^)]*)\)\s*$/);
  if (!m) return <span className={className}>{name}</span>;
  const [, base, qualifier] = m;
  return (
    <span className={className}>
      {base}{" "}
      <span
        className={ALARMING.test(qualifier) ? "font-semibold text-slate-900" : "text-muted"}
        title={ALARMING.test(qualifier) ? "This is the part that makes the route serious" : undefined}
      >
        ({qualifier})
      </span>
    </span>
  );
}

// Open to the whole internet, or carrying administrative authority. Deliberately a short
// list: emphasising everything emphasises nothing.
const ALARMING = /0\.0\.0\.0\/0|::\/0|AdministratorAccess|admin|PII|secret/i;
