import { useEffect, useRef, type KeyboardEvent } from "react";

// What the keyboard does, opened with "?". The keys are few on purpose: moving through the
// route queue and acting on a route are the jobs done thirty times in a row, and the rest
// of the page is a click away. Triage and Assign keep their second step from the keyboard
// too: the key shows the options, and nothing is saved until one is chosen.

const ANYWHERE: [string[], string][] = [
  [["⌘", "K"], "Search assets and findings (Ctrl K on Windows and Linux)"],
  [["?"], "Show these shortcuts"],
  [["Esc"], "Close the search or this window"],
];

const ON_THE_LIST: [string[], string][] = [
  [["j"], "Next route"],
  [["k"], "Previous route"],
  [["Enter"], "Open the route's detail"],
  [["t"], "Triage it: accept the risk, mark it a false positive, or note a control"],
  [["a"], "Assign it: open a ticket with an owner"],
];

export default function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const dialog = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);

  // Focus moves into the window, and back to where it was when the window closes.
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialog.current?.focus();
    return () => previous?.focus();
  }, []);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape" || e.key === "?") {
      e.preventDefault();
      onClose();
    } else if (e.key === "Tab") {
      // One control inside: Tab stays on it rather than wandering off behind the backdrop.
      e.preventDefault();
      closeButton.current?.focus();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-[12vh]" onClick={onClose}>
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby="shortcuts-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
        className="w-full max-w-md rounded-2xl border border-edge bg-panel p-5 shadow-lift outline-hidden"
      >
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 id="shortcuts-title" className="text-[15px] font-semibold text-slate-900">
            Keyboard shortcuts
          </h2>
          <button
            ref={closeButton}
            type="button"
            onClick={onClose}
            aria-label="Close the keyboard shortcuts"
            className="rounded border border-edge px-1.5 py-0.5 text-[12px] text-slate-500 transition hover:border-accent hover:text-accent"
          >
            esc
          </button>
        </div>
        <Keys title="Anywhere" rows={ANYWHERE} />
        <Keys title="On the attack paths list" rows={ON_THE_LIST} />
        <p className="mt-3 text-[12px] leading-snug text-muted">
          Triage and Assign still take a second step: the key shows the options, and nothing is saved until you choose one.
        </p>
      </div>
    </div>
  );
}

function Keys({ title, rows }: { title: string; rows: [string[], string][] }) {
  return (
    <section className="mt-3 first-of-type:mt-0">
      <h3 className="text-[12px] font-semibold text-muted">{title}</h3>
      <dl className="mt-1.5 grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1.5">
        {rows.map(([keys, what]) => (
          <div key={what} className="contents">
            <dt className="flex gap-1">
              {keys.map((k) => (
                <kbd
                  key={k}
                  className="min-w-6 rounded border border-edge bg-ink px-1.5 py-0.5 text-center text-[12px] tabular-nums text-slate-700"
                >
                  {k}
                </kbd>
              ))}
            </dt>
            <dd className="text-[13px] leading-snug text-slate-700">{what}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
