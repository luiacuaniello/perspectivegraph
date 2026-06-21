// A tiny "ⓘ" affordance with a hover/focus tooltip. Used to explain domain jargon
// (KEV, EPSS, Monte Carlo, choke point…) in plain language without cluttering the
// UI — so a first-time user can self-serve the meaning of every number on screen.
interface Props {
  text: string;
  className?: string;
}

export default function InfoTip({ text, className }: Props) {
  return (
    <span className={`group/tip relative inline-flex align-middle ${className ?? ""}`}>
      <button
        type="button"
        aria-label={text}
        className="grid h-3.5 w-3.5 cursor-help place-items-center rounded-full border border-slate-300 text-[8px] font-bold leading-none text-slate-400 transition hover:border-accent hover:text-accent focus:outline-none"
      >
        i
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-30 mt-1.5 w-56 -translate-x-1/2 rounded-lg border border-edge bg-slate-900/95 px-3 py-2 text-[11px] font-normal normal-case leading-relaxed tracking-normal text-slate-100 opacity-0 shadow-lg transition-opacity duration-150 group-hover/tip:opacity-100 group-focus-within/tip:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}
