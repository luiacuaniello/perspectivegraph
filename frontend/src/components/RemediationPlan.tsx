import { useState } from "react";
import type { Fix } from "../api/client";
import { AlertTriangleIcon, CheckIcon, TargetIcon, WrenchIcon } from "./icons";

function FixRow({ fix, rank, cumulative }: { fix: Fix; rank: number; cumulative: number }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(fix.content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="overflow-hidden rounded-xl border border-edge bg-panel">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-slate-50"
      >
        <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-accent/15 text-[11px] font-bold tabular-nums text-accent">
          {rank}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="shrink-0 rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
              {fix.kind}
            </span>
            <span className="truncate text-sm font-medium text-slate-800">{fix.title}</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-500">
            <span>
              cuts {fix.pathCount} attack path{fix.pathCount === 1 ? "" : "s"} ·{" "}
              {(fix.coveragePct * 100).toFixed(0)}% of critical risk
            </span>
            {fix.verification &&
              (fix.verification.verified ? (
                <span
                  className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700"
                  title="Independently simulated (what-if): removing this edge actually removes the paths and drops the risk."
                >
                  <CheckIcon className="h-3 w-3" /> verified · removes {fix.verification.pathsEliminated} path
                  {fix.verification.pathsEliminated === 1 ? "" : "s"}
                  {fix.verification.riskReductionPct >= 0.05
                    ? ` · −${fix.verification.riskReductionPct.toFixed(1)}%`
                    : ""}
                </span>
              ) : (
                <span
                  className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700"
                  title="Simulating this fix did not measurably reduce paths/risk - review before applying."
                >
                  <AlertTriangleIcon className="h-3 w-3" /> unverified
                </span>
              ))}
          </div>
        </div>
        {/* Cumulative coverage bar */}
        <div className="hidden w-40 shrink-0 items-center gap-2 sm:flex">
          <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink">
            <span
              className="block h-full rounded-full bg-accent/70"
              style={{ width: `${Math.min(100, cumulative * 100)}%` }}
            />
          </span>
          <span className="w-9 text-right text-[10px] tabular-nums text-slate-500">
            {(cumulative * 100).toFixed(0)}%
          </span>
        </div>
        <span className="shrink-0 text-slate-500">{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div className="border-t border-edge px-4 py-3">
          <p className="mb-2 text-xs leading-relaxed text-slate-500">{fix.rationale}</p>
          <div className="mb-2 flex items-center justify-between">
            <span className="font-mono text-[10px] text-slate-500">{fix.filename}</span>
            <button
              onClick={copy}
              className="inline-flex items-center gap-1 rounded-md border border-edge px-2.5 py-1 text-[11px] text-slate-500 transition hover:border-slate-500 hover:text-slate-700"
            >
              {copied && <CheckIcon className="h-3 w-3" />}
              {copied ? "copied" : "copy"}
            </button>
          </div>
          <pre className="max-h-72 overflow-auto rounded-lg bg-ink p-3 font-mono text-[11px] leading-relaxed text-slate-600">
            {fix.content}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function RemediationPlan({
  plan,
  pathCount,
}: {
  plan: Fix[];
  pathCount: number;
}) {
  if (pathCount === 0) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/[0.06] p-5 text-sm text-emerald-700">
        <CheckIcon className="h-4 w-4 shrink-0" />
        No critical attack paths - nothing to remediate.
      </div>
    );
  }

  const totalCoverage = plan.reduce((acc, f) => acc + f.coveragePct, 0);
  const pathsCut = plan.reduce((acc, f) => acc + f.pathCount, 0);
  const residual = pathCount - pathsCut;

  return (
    <div className="flex flex-col gap-4">
      {/* Headline summary - the pitch */}
      <div className="rounded-xl border border-edge bg-panel shadow-card p-5">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-slate-500">
          <TargetIcon className="h-4 w-4 text-accent" />
          Optimized remediation plan
        </div>
        <p className="mt-2 text-sm text-slate-700">
          <span className="text-lg font-bold text-slate-900">{plan.length}</span> fix
          {plan.length === 1 ? "" : "es"} eliminate{" "}
          <span className="text-lg font-bold text-accent">{(totalCoverage * 100).toFixed(0)}%</span> of
          critical-path risk across <span className="font-semibold">{pathsCut}</span> of {pathCount}{" "}
          attack paths.
        </p>
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-ink">
          <div
            className="h-full rounded-full bg-accent/70"
            style={{ width: `${Math.min(100, totalCoverage * 100)}%` }}
          />
        </div>
        {residual > 0 && (
          <p className="mt-2 text-[11px] text-amber-700/80">
            {residual} path{residual === 1 ? " has" : "s have"} no automated remediation - review
            manually.
          </p>
        )}
      </div>

      {/* Ranked fixes */}
      {plan.length > 0 && (
        <div className="flex flex-col gap-2">
          {(() => {
            let cumulative = 0;
            return plan.map((fix, i) => {
              cumulative += fix.coveragePct;
              return <FixRow key={fix.filename + i} fix={fix} rank={i + 1} cumulative={cumulative} />;
            });
          })()}
        </div>
      )}

      {plan.length === 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/[0.06] p-4 text-xs text-amber-700">
          <WrenchIcon className="h-4 w-4 shrink-0" />
          No automated remediation matched these paths - they need manual review.
        </div>
      )}
    </div>
  );
}
