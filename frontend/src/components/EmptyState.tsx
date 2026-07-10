import { GemIcon, GlobeIcon, ShieldIcon } from "./icons";

// Shown on first run when the graph is empty: instead of a blank dashboard, tell
// a newcomer exactly what this does and the one command that lights it up.
export default function EmptyState() {
  return (
    <div className="grid h-full place-items-center">
      <div className="max-w-xl rounded-2xl border border-edge bg-panel shadow-card p-8 text-center">
        <span className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-2xl bg-accent/12 text-accent">
          <ShieldIcon className="h-6 w-6" />
        </span>
        <h2 className="text-lg font-semibold text-slate-900">No data yet - let’s light it up</h2>
        <p className="mx-auto mt-2 max-w-md text-[13px] leading-relaxed text-slate-600">
          PerspectiveGraph correlates the output of the scanners you already run into{" "}
          <span className="font-medium text-slate-800">reachable attack paths</span> - from{" "}
          <GlobeIcon className="inline h-3.5 w-3.5 text-accent align-[-2px]" /> internet exposure to{" "}
          <GemIcon className="inline h-3.5 w-3.5 text-amber-700 align-[-2px]" /> your sensitive assets.
        </p>

        <div className="mt-5 rounded-xl bg-ink px-4 py-3 text-left">
          <div className="mb-1 text-[11px] font-medium text-muted">
            Feed the sample data
          </div>
          <code className="block font-mono text-[13px] text-teal-700">make seed</code>
          <code className="mt-1 block font-mono text-[12px] text-slate-500">
            make seed-discovery <span className="text-slate-400"># + Kubernetes, cloud network &amp; IAM privesc</span>
          </code>
        </div>

        <p className="mt-4 text-[11px] text-slate-400">
          Paths appear within one analysis cycle (~30s) - this page refreshes itself.
        </p>
      </div>
    </div>
  );
}
