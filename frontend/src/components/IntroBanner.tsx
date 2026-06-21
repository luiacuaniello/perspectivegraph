import { useState } from "react";
import { CheckIcon, GemIcon, GlobeIcon, LayersIcon, XIcon, ZapIcon } from "./icons";
import Button from "./ui/Button";

// First-run explainer: a newcomer to attack-path tooling needs the mental model
// before the numbers mean anything. Dismissible, remembered in localStorage, and
// re-openable from the header "How to read this" button.
const KEY = "pg_intro_dismissed_v1";

export function useIntroDismissed() {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(KEY) === "1";
    } catch {
      return false;
    }
  });
  const dismiss = () => {
    try {
      localStorage.setItem(KEY, "1");
    } catch {
      /* ignore */
    }
    setDismissed(true);
  };
  const reopen = () => {
    try {
      localStorage.removeItem(KEY);
    } catch {
      /* ignore */
    }
    setDismissed(false);
  };
  return { dismissed, dismiss, reopen };
}

function FlowChip({
  icon,
  label,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  tone: string;
}) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium ${tone}`}>
      {icon}
      {label}
    </span>
  );
}

export default function IntroBanner({ onDismiss }: { onDismiss: () => void }) {
  return (
    <section className="relative shrink-0 rounded-xl border border-accent/25 bg-gradient-to-br from-accent/[0.07] to-accent/[0.02] p-5">
      <button
        onClick={onDismiss}
        aria-label="Dismiss"
        className="absolute right-3 top-3 grid h-6 w-6 place-items-center rounded-md text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
      >
        <XIcon className="h-3.5 w-3.5" />
      </button>

      <h2 className="text-sm font-semibold text-slate-900">How to read this dashboard</h2>
      <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-slate-600">
        PerspectiveGraph doesn’t list every vulnerability — it shows the <span className="font-medium text-slate-800">routes an
        attacker could actually walk</span>. Each <span className="font-medium text-slate-800">attack path</span> starts
        where the internet can reach you and ends at something worth stealing:
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-slate-500">
        <FlowChip
          icon={<GlobeIcon className="h-3.5 w-3.5" />}
          label="Internet-exposed (entry)"
          tone="bg-accent/12 text-accent"
        />
        <span className="text-slate-400">→</span>
        <FlowChip icon={<LayersIcon className="h-3.5 w-3.5" />} label="your assets, CVEs, identities" tone="bg-slate-500/10 text-slate-600" />
        <span className="text-slate-400">→</span>
        <FlowChip
          icon={<GemIcon className="h-3.5 w-3.5" />}
          label="Crown jewel (target)"
          tone="bg-amber-500/15 text-amber-700"
        />
      </div>

      <ul className="mt-4 grid gap-x-6 gap-y-2 text-[12.5px] text-slate-600 sm:grid-cols-2">
        <li className="flex gap-2">
          <span className="font-semibold text-red-600">%</span>
          <span>
            The percentage is the <span className="font-medium text-slate-800">exploit likelihood</span> of that whole
            route — higher means easier for an attacker. Start at the top.
          </span>
        </li>
        <li className="flex gap-2">
          <ZapIcon className="mt-0.5 h-4 w-4 shrink-0 text-red-600" />
          <span>
            A live-activity marker means the path is <span className="font-medium text-slate-800">runtime-confirmed</span> —
            something is exploiting it right now, not just in theory.
          </span>
        </li>
        <li className="flex gap-2">
          <span className="font-semibold text-accent">↳</span>
          <span>
            Open a path to see its <span className="font-medium text-slate-800">kill chain</span> and copy-paste
            <span className="font-medium text-slate-800"> remediation</span> that cuts it.
          </span>
        </li>
        <li className="flex gap-2">
          <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
          <span>
            <span className="font-medium text-slate-800">Remediation</span> shows the fewest fixes that remove the most
            risk — the choke points. Fix those first.
          </span>
        </li>
      </ul>

      <div className="mt-4 flex items-center gap-3">
        <Button variant="primary" size="md" onClick={onDismiss}>
          Got it
        </Button>
        <span className="text-[11px] text-slate-400">You can reopen this from “How to read this” in the header.</span>
      </div>
    </section>
  );
}
