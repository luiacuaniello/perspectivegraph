import { useEffect, useRef, useState } from "react";
import { exportUrl } from "../api/client";
import Button from "./ui/Button";

// Exports behind one control. They were two buttons on every page, "↓ OSCAL" and "↓ SIEM",
// which gave two niche downloads the same weight as the application scope that changes
// every number on screen. Each entry now also says who it is for, which the bare format
// name never did.
//
// The GraphQL playground rides along under its own heading: it is the other way data leaves
// the dashboard, and it lost its place when the sidebar went.
export default function ExportMenu({ canExport, showPlayground }: { canExport: boolean; showPlayground: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointer = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!canExport && !showPlayground) return null;

  const close = () => setOpen(false);
  const item = "flex flex-col gap-0.5 rounded-md px-3 py-2 text-left transition hover:bg-panel-2 focus:bg-panel-2 focus:outline-hidden";

  return (
    <div ref={ref} className="relative shrink-0">
      <Button
        variant="secondary"
        size="md"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Export"
        icon={
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M10 3v9M6 8.5l4 4 4-4M4 16h12" />
          </svg>
        }
      >
        <span className="hidden xl:inline">Export</span>
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 top-full z-40 mt-1.5 w-72 rounded-lg border border-edge bg-panel p-1 shadow-lift">
          {canExport && (
            <>
              <a role="menuitem" href={exportUrl("oscal")} download="perspectivegraph-oscal.json" onClick={close} className={item}>
                <span className="text-[13px] font-medium text-slate-800">OSCAL assessment results</span>
                <span className="text-[12px] text-muted">For GRC and auditors · JSON</span>
              </a>
              <a role="menuitem" href={exportUrl("ndjson")} download="perspectivegraph-enrichment.ndjson" onClick={close} className={item}>
                <span className="text-[13px] font-medium text-slate-800">SIEM enrichment</span>
                <span className="text-[12px] text-muted">Per-asset risk for Splunk, Elastic, Sentinel · NDJSON</span>
              </a>
            </>
          )}
          {showPlayground && (
            <>
              {canExport && <div className="my-1 h-px bg-edge" role="separator" />}
              {/* Relative path: served through the dashboard's own origin (nginx proxies
                  /graphql to the backend), so it works on any host. Offered only while the
                  API is open: GraphiQL cannot carry a bearer token. */}
              <a role="menuitem" href="/graphql" target="_blank" rel="noreferrer" onClick={close} className={item}>
                <span className="text-[13px] font-medium text-slate-800">GraphQL playground ↗</span>
                <span className="text-[12px] text-muted">Query the API directly</span>
              </a>
            </>
          )}
        </div>
      )}
    </div>
  );
}
