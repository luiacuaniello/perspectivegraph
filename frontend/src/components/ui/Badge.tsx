import type { ReactNode } from "react";

export type Tone = "neutral" | "danger" | "warn" | "ok" | "info" | "accent";

const TONE: Record<Tone, string> = {
  neutral: "bg-slate-500/10 text-slate-600",
  danger: "bg-red-500/15 text-red-700",
  warn: "bg-amber-500/15 text-amber-700",
  ok: "bg-emerald-500/15 text-emerald-700",
  info: "bg-accent/15 text-accent",
  accent: "bg-accent/15 text-accent",
};

// Badge is the one chip vocabulary: a tone (semantic color), an optional icon,
// and an optional dashed outline for "this is a heuristic / verify me" signals.
// `title` carries the plain-language explanation on hover.
export default function Badge({
  tone = "neutral",
  icon,
  children,
  title,
  dashed = false,
  className = "",
}: {
  tone?: Tone;
  icon?: ReactNode;
  children: ReactNode;
  title?: string;
  dashed?: boolean;
  className?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium ${TONE[tone]} ${
        dashed ? "border border-dashed border-current/40" : ""
      } ${className}`}
    >
      {icon}
      {children}
    </span>
  );
}
