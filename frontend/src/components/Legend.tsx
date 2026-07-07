import { useState } from "react";
import Badge from "./ui/Badge";
import { AlertTriangleIcon, CheckIcon, CrosshairIcon, FlameIcon, GemIcon, GlobeIcon, ZapIcon } from "./icons";

// Legend decodes the dense badge vocabulary in one place, so a first-time reader
// isn't left guessing what "KEV", "assumed", "heuristic join" or "unsigned" mean.
// Collapsible - open it once, dismiss it, get on with the work.
export default function Legend() {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-xl border border-edge bg-panel shadow-card">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2 text-[13px] font-medium text-muted">
          <svg viewBox="0 0 20 20" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={1.6}>
            <circle cx="10" cy="10" r="7.5" />
            <path d="M10 9v4M10 6.5h.01" strokeLinecap="round" />
          </svg>
          Legend - what the badges mean
        </span>
        <span className="text-muted">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="grid gap-x-6 gap-y-3 border-t border-edge px-4 py-3.5 text-[11px] text-muted sm:grid-cols-2 lg:grid-cols-3">
          <Row badge={<Badge tone="info" icon={<GlobeIcon className="h-3 w-3" />}>internet-exposed</Badge>}>
            A valid attack <b>entry point</b> (seed) - reachable from the internet.
          </Row>
          <Row badge={<Badge tone="warn" icon={<GemIcon className="h-3 w-3" />}>crown jewel</Badge>}>
            A high-value <b>target</b>. <i>(inferred)</i> = guessed from a sensitive name, not tagged.
          </Row>
          <Row badge={<Badge tone="danger" icon={<ZapIcon className="h-3 w-3" />}>ACTIVELY EXPLOITED</Badge>}>
            A node on the path has a <b>live Falco runtime alert</b> - exercised now, not theoretical.
          </Row>
          <Row badge={<Badge tone="danger" icon={<FlameIcon className="h-3 w-3" />} className="font-bold uppercase">KEV</Badge>}>
            CVE in CISA’s <b>Known Exploited Vulnerabilities</b> catalog - exploited in the wild.
          </Row>
          <Row badge={<span className="text-[10px] font-medium text-emerald-700">● high confidence</span>}>
            How much to <b>trust the score</b>: evidence-backed weights raise it, guesses lower it.
          </Row>
          <Row badge={<Badge tone="ok">KEV</Badge>}>
            Hop weight is <b>evidence</b> (KEV / EPSS / runtime) - observed, not assumed.
          </Row>
          <Row badge={<Badge tone="neutral">assumed</Badge>}>
            Hop weight is an <b>estimate</b> (severity/CVSS-derived or a topology default).
          </Row>
          <Row badge={<Badge tone="warn" dashed icon={<AlertTriangleIcon className="h-3 w-3" />}>heuristic join</Badge>}>
            This hop was <b>inferred</b> by the resolver (e.g. container→image), not asserted - verify it.
          </Row>
          <Row badge={<Badge tone="danger" icon={<AlertTriangleIcon className="h-3 w-3" />}>unsigned</Badge>}>
            Supply-chain: image signature <b>not verified</b> (cosign) - a tampering vector.
          </Row>
          <Row badge={<Badge tone="info" icon={<CheckIcon className="h-3 w-3" />}>validated real</Badge>}>
            A <b>red-team / BAS</b> verdict: the path was tested and confirmed exploitable (vs <i>refuted</i> = false positive).
          </Row>
          <Row
            badge={
              <span className="inline-flex items-center gap-1 rounded bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                <CrosshairIcon className="h-3 w-3" />
                T1190 · Initial Access
              </span>
            }
          >
            The <b>MITRE ATT&amp;CK</b> technique (and tactic) each hop maps to - click it for the technique page.
          </Row>
        </div>
      )}
    </div>
  );
}

function Row({ badge, children }: { badge: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-0.5 shrink-0">{badge}</span>
      <span className="leading-snug">{children}</span>
    </div>
  );
}
