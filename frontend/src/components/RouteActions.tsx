import { useState } from "react";
import { createSuppression, createTicket, type AttackPath, type SuppressionReason } from "../api/client";

// Acting from the row - the other half of the console idea.
//
// Before this the list could only inform: every action lived in the detail panel, so
// triaging ten routes meant ten round trips out of the queue and back. These act in
// place, and because they are what MOVES a route through its lifecycle, they are what
// makes the status channel worth having: a row you assign turns "Fixing" under your
// cursor.
//
// Two steps, always. Both of these are consequential - suppressing hides a finding from
// the board, opening a ticket puts a name against it - so the first click reveals the
// options and the second commits. That is not friction for its own sake: a one-click
// suppress in a dense list is a mis-click away from silently hiding a live route.
//
// Revealed on hover and on keyboard focus. `focus-within` matters more than hover here:
// an action you can only reach with a mouse is not an action for someone tabbing the
// queue.

const REASONS: { value: SuppressionReason; label: string; hint: string }[] = [
  { value: "accept-risk", label: "Accept risk", hint: "A human accepts this exposure, eyes open." },
  { value: "false-positive", label: "False positive", hint: "The path or correlation is not real." },
  { value: "mitigating-control", label: "Mitigated", hint: "A control outside the graph already blocks it." },
  { value: "duplicate", label: "Duplicate", hint: "Tracked under another route or ticket." },
];

// Remembered so the second route you assign does not ask again. It is a display name on
// a ticket, not a credential.
const OWNER_KEY = "pg-owner";

type Mode = "idle" | "triage" | "assign";

export default function RouteActions({ path, onChanged }: { path: AttackPath; onChanged: () => void }) {
  const [mode, setMode] = useState<Mode>("idle");
  const [owner, setOwner] = useState(() => localStorage.getItem(OWNER_KEY) ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const route = `${path.nodes[0]?.name ?? "?"} → ${path.nodes[path.nodes.length - 1]?.name ?? "?"}`;
  const close = () => {
    setMode("idle");
    setErr(null);
  };

  const suppress = async (reason: SuppressionReason) => {
    const name = owner.trim();
    // The API requires an owner, and it is right to: a suppression is somebody deciding
    // this exposure is acceptable, and a decision with no name on it is how a finding
    // disappears with nobody answerable for it. An earlier version of this defaulted to
    // "unattributed" to save a keystroke, which quietly defeated that control.
    if (!name) {
      setErr("who is accepting this? a suppression needs a name against it");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await createSuppression({ pathId: path.id, reason, owner: name });
      localStorage.setItem(OWNER_KEY, name);
      close();
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "could not suppress");
    } finally {
      setBusy(false);
    }
  };

  const assign = async () => {
    const name = owner.trim();
    if (!name) {
      setErr("a name is required - a ticket nobody owns is a ticket nobody does");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await createTicket({ pathId: path.id, owner: name, route });
      localStorage.setItem(OWNER_KEY, name);
      close();
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "could not open a ticket");
    } finally {
      setBusy(false);
    }
  };

  // Stop a click on the controls from also selecting the row underneath.
  const swallow = (e: React.MouseEvent | React.KeyboardEvent) => e.stopPropagation();

  if (mode === "idle") {
    return (
      <div
        className="flex shrink-0 items-center gap-1 opacity-0 transition group-hover/row:opacity-100 group-focus-within/row:opacity-100"
        onClick={swallow}
      >
        <RowButton onClick={() => setMode("triage")} title="Triage this route: accept, dismiss or note a control">
          Triage
        </RowButton>
        <RowButton onClick={() => setMode("assign")} title="Open an owned remediation ticket for this route">
          Assign
        </RowButton>
      </div>
    );
  }

  return (
    <div className="flex shrink-0 flex-wrap items-center justify-end gap-1" onClick={swallow}>
      {mode === "triage" ? (
        <>
          {/* Asked once, then remembered - the same name the ticket flow uses. */}
          {!owner.trim() && (
            <input
              autoFocus
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              onKeyDown={(e) => e.key === "Escape" && close()}
              placeholder="your name"
              aria-label="Who is accepting this"
              className="w-24 rounded-md border border-edge bg-panel px-1.5 py-0.5 text-[11px] text-slate-900 outline-none focus:border-accent"
            />
          )}
          {REASONS.map((r) => (
            <RowButton key={r.value} onClick={() => void suppress(r.value)} title={r.hint} disabled={busy}>
              {r.label}
            </RowButton>
          ))}
        </>
      ) : (
        <>
          <input
            autoFocus
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void assign();
              if (e.key === "Escape") close();
            }}
            placeholder="owner"
            aria-label="Ticket owner"
            className="w-24 rounded-md border border-edge bg-panel px-1.5 py-0.5 text-[11px] text-slate-900 outline-none focus:border-accent"
          />
          <RowButton onClick={() => void assign()} disabled={busy} title="Open the ticket">
            {busy ? "…" : "Open"}
          </RowButton>
        </>
      )}
      <RowButton onClick={close} title="Cancel">
        ✕
      </RowButton>
      {err && <span className="w-full text-right text-[10px] text-flag">{err}</span>}
    </div>
  );
}

function RowButton({
  children,
  onClick,
  title,
  disabled,
}: {
  children: React.ReactNode;
  onClick: () => void;
  title: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      disabled={disabled}
      className="rounded-md border border-edge bg-panel px-1.5 py-0.5 text-[10.5px] text-slate-700 transition hover:border-accent hover:text-accent disabled:opacity-50"
    >
      {children}
    </button>
  );
}
