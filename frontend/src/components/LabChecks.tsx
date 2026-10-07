import { useEffect, useState } from "react";
import { fetchLabRuns, type LabCheck, type LabRun } from "../api/client";
import InfoTip from "./InfoTip";

// LabChecks shows how this version's rules were checked against AWS. Each lab builds
// resources on a real account and puts the same question to AWS and to the engine - is this
// bucket open, does this function URL let a stranger in, can this role make itself
// administrator - and records both answers. The records are built into the backend, so they
// describe the engine, not the estate it reads, and every installation shows the same ones:
// the visible text says so, since a reader takes "checked against AWS" to mean their own.
//
// It answers a narrower question than the verdict above it: whether the facts a route's
// steps rest on are right, not whether a whole route can be walked. Without it the page
// read as if nothing had been measured, when the engine is checked against AWS every
// release; with it the "not enough outcomes" verdict keeps its own, narrower scope.
export default function LabChecks() {
  const [runs, setRuns] = useState<LabRun[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    fetchLabRuns()
      .then((r) => alive && setRuns(r))
      .catch((e) => alive && setErr(e instanceof Error ? e.message : "could not load the lab records"));
    return () => {
      alive = false;
    };
  }, []);

  if (err) return <p className="px-1 text-[12px] text-muted">The lab records could not be loaded: {err}</p>;
  if (!runs || runs.length === 0) return null;
  const total = runs.reduce((n, r) => n + r.checks.length, 0);
  const agreed = runs.reduce((n, r) => n + r.agreed, 0);

  return (
    <section aria-labelledby="lab-checks-title" className="rounded-2xl border border-edge bg-panel px-5 py-4">
      <div className="flex items-center gap-1 text-[12px] text-muted">
        <h2 id="lab-checks-title" className="text-[12px] font-normal text-muted">
          Checked against AWS
        </h2>
        <InfoTip text="Each lab builds resources on both sides of a rule, on the project's own AWS account, and takes the verdict from AWS - S3's judgement of a policy, the answer a stranger's request gets, IAM's policy simulator. The records ship with the engine, so every installation shows the same ones, each with the engine version it was run with." />
      </div>
      <p className="mt-1.5 text-[17px] font-semibold tabular-nums text-slate-900">
        {agreed} of {total} answers match AWS's own
      </p>
      <p className="mt-2 max-w-[70ch] text-[13px] leading-relaxed text-slate-600">
        The project's own labs, on the project's own AWS account - not checks of your estate. Each puts the facts a
        route's steps rest on to AWS and to the engine: whether a bucket is open or a role can escalate, not whether a
        whole route can be walked. That is the question above, and it needs real outcomes.
      </p>
      <ul className="mt-3 flex flex-col divide-y divide-edge/70">
        {runs.map((r) => (
          <LabRunRow key={r.lab} run={r} />
        ))}
      </ul>
    </section>
  );
}

function LabRunRow({ run }: { run: LabRun }) {
  return (
    <li className="py-2">
      <details className="group">
        <summary className="flex cursor-pointer list-none flex-wrap items-baseline gap-x-3 gap-y-0.5 text-[13px] [&::-webkit-details-marker]:hidden">
          <span className="min-w-0 flex-1 font-medium text-slate-800">{run.title}</span>
          <span className="tabular-nums text-slate-700">
            {run.agreed} of {run.checks.length} agree
            {run.disagreed > 0 && <span className="font-medium text-flag"> · {run.disagreed} disagree</span>}
            {run.unsettled > 0 && <span> · {run.unsettled} unsettled</span>}
          </span>
          <span aria-hidden="true" className="text-muted transition group-open:rotate-90">
            ›
          </span>
        </summary>
        <p className="mt-1.5 text-[12px] text-muted">
          Run {new Date(run.ranAt).toLocaleDateString()} with engine {run.engine}, in {run.region}, cost {run.cost}.
          Run it again: <code className="font-mono text-slate-700">{run.command}</code>
        </p>
        {/* Focusable, so a keyboard can scroll the table where a phone is narrower than it. */}
        <div
          className="mt-2 overflow-x-auto rounded focus-visible:outline focus-visible:outline-2 focus-visible:outline-slate-500"
          tabIndex={0}
          role="region"
          aria-label={`The checks of ${run.title}`}
        >
          <table className="w-full min-w-[36rem] text-left text-[12px]">
            <caption className="sr-only">Each question put both to AWS and to the engine: {run.title}</caption>
            <thead>
              <tr className="text-muted">
                <th scope="col" className="py-1 pr-3 font-normal">Case</th>
                <th scope="col" className="py-1 pr-3 font-normal">Question</th>
                <th scope="col" className="py-1 pr-3 font-normal">AWS</th>
                <th scope="col" className="py-1 pr-3 font-normal">Engine</th>
                <th scope="col" className="py-1 font-normal">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge/60">
              {run.checks.map((c, i) => (
                <CheckRow key={`${c.case}-${i}`} check={c} />
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </li>
  );
}

function CheckRow({ check: c }: { check: LabCheck }) {
  return (
    <tr className="align-top">
      <td className="py-1.5 pr-3 font-mono text-slate-700">{c.case}</td>
      <td className="py-1.5 pr-3 text-slate-700">
        {c.question}
        <span className="block text-muted">
          asked: {c.referee}
          {c.note ? ` · ${c.note}` : ""}
        </span>
      </td>
      <td className="py-1.5 pr-3 text-slate-800">{c.aws}</td>
      <td className="py-1.5 pr-3 text-slate-800">{c.engine}</td>
      <td className={`py-1.5 font-medium ${c.verdict === "disagree" ? "text-flag" : "text-slate-700"}`}>{c.verdict}</td>
    </tr>
  );
}
