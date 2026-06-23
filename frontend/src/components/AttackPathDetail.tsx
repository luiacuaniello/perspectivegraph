import { useState } from "react";
import {
  aiExplain,
  closeTicket,
  createSuppression,
  createTicket,
  createValidation,
  deleteSuppression,
  humanDuration,
  openRemediationPR,
  runWhatIf,
  type AttackPath,
  type Node,
  type Step,
  type SuppressionReason,
  type ValidationOutcome,
  type WhatIfResult,
} from "../api/client";
import {
  AlertTriangleIcon,
  AssetIcon,
  CheckIcon,
  CrosshairIcon,
  FlameIcon,
  GemIcon,
  GlobeIcon,
  ScissorsIcon,
  TicketIcon,
  ZapIcon,
} from "./icons";
import InfoTip from "./InfoTip";
import Button from "./ui/Button";
import Badge, { type Tone } from "./ui/Badge";

interface Props {
  path: AttackPath;
  onShowInGraph?: () => void;
  // Called after a successful suppress / un-suppress so the dashboard can refetch.
  onTriaged?: () => void;
  // Show the "Explain (AI)" control only when the backend has Claude configured.
  aiEnabled?: boolean;
}

const REASONS: { value: SuppressionReason; label: string; hint: string }[] = [
  { value: "accept-risk", label: "Accept risk", hint: "A human accepts this exposure, eyes open." },
  { value: "false-positive", label: "False positive", hint: "The path or correlation isn’t real." },
  { value: "mitigating-control", label: "Mitigating control", hint: "A control outside the graph already blocks it." },
  { value: "duplicate", label: "Duplicate", hint: "Tracked under another path or ticket." },
];

const reasonLabel = (r: string) => REASONS.find((x) => x.value === r)?.label ?? r;

const TTL_OPTIONS = [
  { value: 0, label: "No expiry" },
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];

const fieldClass =
  "rounded-md border border-edge bg-panel px-2 py-1.5 text-[12px] text-slate-700 outline-none focus:border-accent";

// TriageControl is the suppression loop: record a triage decision (reason +
// accountable owner + optional expiry) that takes this path off the active board,
// un-suppress one already triaged, or show the in-force decision.
function TriageControl({ path, onTriaged }: { path: AttackPath; onTriaged?: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<SuppressionReason>("accept-risk");
  const [owner, setOwner] = useState("");
  const [note, setNote] = useState("");
  const [ttlDays, setTtlDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = () => {
    if (!owner.trim()) {
      setErr("Owner is required - a suppression must be accountable.");
      return;
    }
    setBusy(true);
    setErr(null);
    createSuppression({ pathId: path.id, reason, owner: owner.trim(), note: note.trim() || undefined, ttlDays: ttlDays || undefined })
      .then(() => {
        setOpen(false);
        onTriaged?.();
      })
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  const unsuppress = () => {
    setBusy(true);
    setErr(null);
    deleteSuppression(path.id)
      .then(() => onTriaged?.())
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  if (path.suppressed && path.suppression) {
    const s = path.suppression;
    return (
      <div className="w-full rounded-lg border border-slate-300 bg-slate-100/70 px-3.5 py-2.5 text-[12px]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-slate-600">
            <span className="font-semibold text-slate-700">Suppressed</span> · {reasonLabel(s.reason)} · {s.owner}
            {s.expiresAt ? ` · until ${new Date(s.expiresAt).toLocaleDateString()}` : " · no expiry"}
          </span>
          <Button variant="secondary" onClick={unsuppress} disabled={busy}>
            {busy ? "…" : "Un-suppress"}
          </Button>
        </div>
        {s.note && <div className="mt-1 italic text-slate-500">“{s.note}”</div>}
        {err && <div className="mt-1 text-red-600">{err}</div>}
      </div>
    );
  }

  if (!open) {
    return (
      <Button
        variant="secondary"
        onClick={() => setOpen(true)}
        title="Triage this path: accept the risk, mark a false positive, note a mitigating control or a duplicate"
      >
        ⊘ Suppress / triage
      </Button>
    );
  }

  return (
    <div className="w-full rounded-lg border border-edge bg-ink/60 p-3.5 text-[12px]">
      <div className="mb-2 font-semibold text-slate-700">Triage this attack path</div>
      <div className="grid gap-2.5 sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-muted">Disposition</span>
          <select value={reason} onChange={(e) => setReason(e.target.value as SuppressionReason)} className={fieldClass}>
            {REASONS.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <span className="text-[11px] text-slate-400">{REASONS.find((r) => r.value === reason)?.hint}</span>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-muted">Owner (accountable)</span>
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="you@team or team name" className={fieldClass} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-muted">Expiry</span>
          <select value={ttlDays} onChange={(e) => setTtlDays(Number(e.target.value))} className={fieldClass}>
            {TTL_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 sm:col-span-2">
          <span className="text-muted">Note (optional)</span>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="why is this being suppressed?" className={fieldClass} />
        </label>
      </div>
      {err && <div className="mt-2 text-red-600">{err}</div>}
      <div className="mt-3 flex items-center gap-2">
        <Button variant="primary" onClick={submit} disabled={busy}>
          {busy ? "Suppressing…" : "Suppress path"}
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            setOpen(false);
            setErr(null);
          }}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}

// TicketControl is the last mile of the action loop: turn a path into an owned,
// tracked remediation ticket (and close it when done). One open ticket per path.
function TicketControl({ path, onChanged }: { path: AttackPath; onChanged?: () => void }) {
  const [open, setOpen] = useState(false);
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const route = path.nodes.map((n) => n.name).join(" → ");

  const submit = () => {
    if (!owner.trim()) {
      setErr("Owner is required.");
      return;
    }
    setBusy(true);
    setErr(null);
    createTicket({ pathId: path.id, owner: owner.trim(), route })
      .then(() => {
        setOpen(false);
        onChanged?.();
      })
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  const close = () => {
    if (!path.ticket) return;
    setBusy(true);
    setErr(null);
    closeTicket(path.ticket.id)
      .then(() => onChanged?.())
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  if (path.ticket) {
    return (
      <div className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-700">
        <TicketIcon className="h-3.5 w-3.5" />
        <span>Ticketed · {path.ticket.owner}</span>
        {path.ticket.externalUrl && (
          <a href={path.ticket.externalUrl} target="_blank" rel="noreferrer" className="underline">
            open ↗
          </a>
        )}
        <Button variant="ghost" onClick={close} disabled={busy} className="text-emerald-700 hover:bg-emerald-500/10">
          {busy ? "…" : "close"}
        </Button>
        {err && <span className="text-red-600">{err}</span>}
      </div>
    );
  }
  if (!open) {
    return (
      <Button variant="secondary" onClick={() => setOpen(true)} icon={<TicketIcon className="h-3.5 w-3.5" />} title="Open an owned, tracked remediation ticket for this path">
        Create ticket
      </Button>
    );
  }
  return (
    <div className="inline-flex flex-wrap items-center gap-2">
      <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner (you@team)" className={fieldClass} />
      <Button variant="primary" onClick={submit} disabled={busy}>
        {busy ? "…" : "Open ticket"}
      </Button>
      <Button
        variant="ghost"
        onClick={() => {
          setOpen(false);
          setErr(null);
        }}
      >
        Cancel
      </Button>
      {err && <span className="text-[11px] text-red-600">{err}</span>}
    </div>
  );
}

// AiExplainControl asks Claude to explain this path in plain English. Renders the
// button plus a full-width answer block that wraps onto its own line.
function AiExplainControl({ path }: { path: AttackPath }) {
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const explain = () => {
    setBusy(true);
    setErr(null);
    aiExplain(path.id)
      .then(setText)
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Button variant="secondary" onClick={explain} disabled={busy} title="Explain this path in plain English with Claude">
        {busy ? "Explaining…" : text ? "Re-explain (AI)" : "Explain (AI)"}
      </Button>
      {err && <span className="text-[12px] text-red-600">{err}</span>}
      {text && (
        <p className="basis-full whitespace-pre-wrap rounded-lg border border-edge bg-ink px-3 py-2 text-[13px] leading-relaxed text-slate-700">
          {text}
        </p>
      )}
    </>
  );
}

// RemediationPRControl opens a pull request with this path's generated fix
// (branch + commit + PR). The backend needs a GitHub token; admin role when auth
// is on. Closes the loop: the fix arrives as a PR to review, not a copy-paste.
function RemediationPRControl({ path }: { path: AttackPath }) {
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (url) {
    return (
      <a
        href={url}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-700 underline"
      >
        Fix PR opened ↗
      </a>
    );
  }
  const open = () => {
    setBusy(true);
    setErr(null);
    openRemediationPR(path.id)
      .then((r) => setUrl(r.url))
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };
  return (
    <span className="inline-flex items-center gap-1.5">
      <Button
        variant="secondary"
        onClick={open}
        disabled={busy}
        icon={<ScissorsIcon className="h-3.5 w-3.5" />}
        title="Open a pull request with the generated fix for this path (needs a GitHub token on the backend)"
      >
        {busy ? "Opening PR…" : "Open fix PR"}
      </Button>
      {err && <span className="text-[11px] text-red-600">{err}</span>}
    </span>
  );
}

// VALIDATION_META maps a red-team/BAS verdict to a chip tone + label.
const VALIDATION_META: Record<ValidationOutcome, { tone: Tone; label: string }> = {
  confirmed: { tone: "info", label: "validated real" },
  refuted: { tone: "neutral", label: "refuted (false positive)" },
  partial: { tone: "warn", label: "partial" },
  missed: { tone: "warn", label: "missed" },
};

const VALIDATION_OPTIONS: { value: ValidationOutcome; label: string }[] = [
  { value: "confirmed", label: "Confirmed - exploitable end-to-end" },
  { value: "refuted", label: "Refuted - not traversable (false positive)" },
  { value: "partial", label: "Partial - partially traversable" },
];

// ValidationControl records a red-team/BAS test result for this path - the
// evidence that turns a modeled path into a tested one (feeds precision/recall).
function ValidationControl({ path, onChanged }: { path: AttackPath; onChanged?: () => void }) {
  const [open, setOpen] = useState(false);
  const [outcome, setOutcome] = useState<ValidationOutcome>("confirmed");
  const [source, setSource] = useState("");
  const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = () => {
    if (!source.trim()) {
      setErr("Source is required - a verdict needs provenance (the tool/tester).");
      return;
    }
    setBusy(true);
    setErr(null);
    createValidation({ pathId: path.id, outcome, source: source.trim(), evidence: evidence.trim() || undefined })
      .then(() => {
        setOpen(false);
        onChanged?.();
      })
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setBusy(false));
  };

  if (!open) {
    return (
      <Button variant="secondary" onClick={() => setOpen(true)} icon={<CheckIcon className="h-3.5 w-3.5" />} title="Record a red-team / BAS test result for this path (confirmed, refuted or partial)">
        {path.validation ? "Re-validate" : "Validate"}
      </Button>
    );
  }
  return (
    <div className="w-full rounded-lg border border-edge bg-ink/60 p-3.5 text-[12px]">
      <div className="mb-2 font-semibold text-slate-700">Record a test result (red-team / BAS)</div>
      <div className="grid gap-2.5 sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-muted">Verdict</span>
          <select value={outcome} onChange={(e) => setOutcome(e.target.value as ValidationOutcome)} className={fieldClass}>
            {VALIDATION_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-muted">Source (tool / tester)</span>
          <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="caldera, attackiq, red-team…" className={fieldClass} />
        </label>
        <label className="flex flex-col gap-1 sm:col-span-2">
          <span className="text-muted">Evidence (optional)</span>
          <input value={evidence} onChange={(e) => setEvidence(e.target.value)} placeholder="link to the run / notes" className={fieldClass} />
        </label>
      </div>
      {err && <div className="mt-2 text-red-600">{err}</div>}
      <div className="mt-3 flex items-center gap-2">
        <Button variant="primary" onClick={submit} disabled={busy}>
          {busy ? "Recording…" : "Record verdict"}
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            setOpen(false);
            setErr(null);
          }}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}

// NodeBadges renders the risk/trust flags on a kill-chain node - one consistent
// chip vocabulary (Badge), tooltips carrying the plain-language meaning.
function NodeBadges({ node }: { node: Node }) {
  const basis = node.crownJewelBasis ?? "";
  const inferredJewel = basis.startsWith("inferred");
  const classifiedJewel = basis.startsWith("classified");
  const jewelTitle = inferredJewel
    ? `Inferred crown jewel (${basis.replace("inferred:", "signal: ")}) - guessed from a sensitive-data signal, not an explicit tag. Verify the classification.`
    : classifiedJewel
      ? `Crown jewel from a real data classifier (${basis.replace("classified:", "")}) - authoritative, not a name guess.`
      : "Crown jewel - a high-value traversal target.";
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {node.internetExposed && (
        <Badge tone="info" icon={<GlobeIcon className="h-3 w-3" />}>
          internet-exposed
        </Badge>
      )}
      {node.crownJewel && (
        <Badge tone="warn" icon={<GemIcon className="h-3 w-3" />} title={jewelTitle}>
          crown jewel{inferredJewel ? " (inferred)" : classifiedJewel ? " (classified)" : ""}
        </Badge>
      )}
      {node.classification && (
        <Badge tone="danger" title={`Data classification: ${node.classification.toUpperCase()} (from a real classifier - Macie/DLP/tag policy).`}>
          {node.classification.toLowerCase()}
        </Badge>
      )}
      {node.secretsScrubbed && (
        <Badge tone="neutral" title="A secret value (token, key, password) was redacted out of this node at ingest - the finding is kept, the credential is not, so the attack map never stores a live secret.">
          secret scrubbed
        </Badge>
      )}
      {node.runtimeAlert && (
        <Badge tone="danger" icon={<ZapIcon className="h-3 w-3" />}>
          runtime alert
        </Badge>
      )}
      {node.kev && (
        <Badge tone="danger" icon={<FlameIcon className="h-3 w-3" />} title="In CISA's Known Exploited Vulnerabilities catalog - exploited in the wild" className="font-bold uppercase">
          KEV
        </Badge>
      )}
      {node.epss != null && node.epss > 0 && (
        <Badge tone="neutral" title="FIRST EPSS - probability of exploitation within 30 days">
          EPSS {(node.epss * 100).toFixed(0)}%
        </Badge>
      )}
      {node.severity && (
        <Badge tone="neutral" className="uppercase">
          {node.severity}
          {node.cvss ? ` · ${node.cvss.toFixed(1)}` : ""}
        </Badge>
      )}
      {node.signed === false && (
        <Badge tone="danger" icon={<AlertTriangleIcon className="h-3 w-3" />} title="Supply-chain: signature NOT verified (cosign) - an unsigned build is a tampering vector.">
          unsigned
        </Badge>
      )}
      {node.signed === true && (
        <Badge tone="ok" title="Supply-chain: image signature verified (cosign).">
          signed
        </Badge>
      )}
      {node.slsaLevel != null && node.slsaLevel > 0 && (
        <Badge tone="neutral" title="SLSA build-provenance level [0..4] - higher is a more trustworthy build.">
          SLSA L{node.slsaLevel}
        </Badge>
      )}
    </span>
  );
}

// Artifact is the shared shape of a generated remediation or detection.
interface Artifact {
  title: string;
  kind: string;
  filename: string;
  content: string;
  rationale: string;
}

function ArtifactCard({ r, tone = "emerald" }: { r: Artifact; tone?: "emerald" | "indigo" }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(r.content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  const badge = tone === "indigo" ? "bg-indigo-500/15 text-indigo-700" : "bg-emerald-500/15 text-emerald-700";

  return (
    <div className="overflow-hidden rounded-xl border border-edge bg-panel shadow-card">
      <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${badge}`}>{r.kind}</span>
          <span className="truncate text-sm font-medium text-slate-800">{r.title}</span>
        </div>
        <Button variant="secondary" onClick={copy} icon={copied ? <CheckIcon className="h-3.5 w-3.5" /> : undefined}>
          {copied ? "copied" : "copy"}
        </Button>
      </div>
      <div className="px-4 py-3">
        <p className="mb-2 text-xs leading-relaxed text-muted">{r.rationale}</p>
        <div className="mb-1 font-mono text-[10px] text-slate-400">{r.filename}</div>
        <pre className="max-h-72 overflow-auto rounded-lg bg-ink p-3 font-mono text-[11px] leading-relaxed text-slate-600">{r.content}</pre>
      </div>
    </div>
  );
}

const CONFIDENCE_TONE: Record<string, string> = {
  high: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700",
  medium: "border-slate-300 bg-slate-500/10 text-slate-600",
  low: "border-amber-500/40 bg-amber-500/10 text-amber-700",
};

const PRIORITY_TONE: Record<string, string> = {
  P1: "bg-red-600 text-white",
  P2: "bg-amber-500/20 text-amber-700",
  P3: "bg-slate-500/15 text-slate-600",
};

// BASIS_META maps a hop's weight provenance to a short label and whether it is
// observed evidence (green) or an estimate/assumption (grey).
const BASIS_META: Record<string, { label: string; evidence: boolean }> = {
  kev: { label: "KEV", evidence: true },
  epss: { label: "EPSS", evidence: true },
  runtime: { label: "runtime", evidence: true },
  cvss: { label: "CVSS", evidence: false },
  severity: { label: "severity", evidence: false },
  heuristic: { label: "assumed", evidence: false },
};

function BasisChip({ basis }: { basis: string }) {
  const meta = BASIS_META[basis];
  if (!meta) return null;
  return (
    <Badge
      tone={meta.evidence ? "ok" : "neutral"}
      title={
        meta.evidence
          ? "This hop's probability rests on observed exploitation evidence (KEV / EPSS / runtime)."
          : "This hop's probability is an estimate - severity/CVSS-derived or an assumed topology default, not observed."
      }
    >
      {meta.label}
    </Badge>
  );
}

export default function AttackPathDetail({ path, onShowInGraph, onTriaged, aiEnabled }: Props) {
  const entry = path.nodes[0];
  const target = path.nodes[path.nodes.length - 1];

  // What-if: cut one edge of this path and show the residual quantified risk.
  const [whatIf, setWhatIf] = useState<{ step: Step; result: WhatIfResult } | null>(null);
  const [cutting, setCutting] = useState<string | null>(null);
  const nameOf = (id: string) => path.nodes.find((n) => n.id === id)?.name ?? id;

  const simulateCut = (step: Step) => {
    const key = `${step.from}->${step.to}`;
    setCutting(key);
    setWhatIf(null);
    runWhatIf([{ from: step.from, to: step.to, type: step.edgeType }])
      .then((result) => setWhatIf({ step, result }))
      .catch(() => setWhatIf(null))
      .finally(() => setCutting(null));
  };

  const hasStatus =
    path.runtimeConfirmed ||
    path.openForSeconds != null ||
    (path.reopens ?? 0) > 0 ||
    path.suppressed ||
    !!path.validation;

  return (
    <div className="flex flex-col gap-4">
      {/* ── Header: identity, score, status, actions ─────────────────── */}
      <header className="flex flex-col gap-3.5 rounded-xl border border-edge bg-panel shadow-card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-widest text-muted">Attack path</div>
            <h2 className="mt-1 flex flex-wrap items-baseline gap-x-2 text-lg font-semibold text-slate-900">
              <span>{entry?.name}</span>
              <span className="text-muted">→</span>
              <span>{target?.name}</span>
            </h2>
            <div className="mt-1 text-xs text-muted">
              {path.steps.length} hops · {path.nodes.map((n) => n.label).join(" → ")}
            </div>
            {path.priorityLabel && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span
                  className={`rounded-md px-1.5 py-0.5 text-[11px] font-bold tabular-nums ${PRIORITY_TONE[path.priorityLabel] ?? PRIORITY_TONE.P3}`}
                  title="Composite triage priority [0,100]: blends exploitability + trust with runtime/KEV corroboration, target sensitivity, and entry blast radius - the 'fix first' signal."
                >
                  {path.priorityLabel} · priority {path.priority?.toFixed(0)}
                </span>
                {path.priorityFactors?.map((f) => (
                  <span key={f} className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[10px] text-slate-600">
                    {f}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            <div className="rounded-lg bg-red-500/15 px-3 py-1 text-xl font-bold tabular-nums text-red-700">
              {(path.score * 100).toFixed(0)}%
            </div>
            <span className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted">
              exploit score
              <InfoTip text="How likely an attacker can walk this whole route - the product of each hop’s probability (p). Higher = easier to exploit." />
            </span>
            {path.scoreCiLow != null &&
              path.scoreCiHigh != null &&
              path.scoreCiHigh - path.scoreCiLow > 0.02 && (
                <span
                  className="flex items-center gap-1 text-[10px] tabular-nums text-muted"
                  title="90% Bayesian credible interval on the score. Each hop's probability is a Beta posterior whose width reflects how much evidence backs it (tight for KEV/runtime, wide for a heuristic guess), propagated through the product. A wide band means the score rests on soft inputs; a narrow one means it's evidence-backed. This is how well we know the inputs - distinct from the 'if correlated' band, which is about the independence assumption."
                >
                  90% CI {(path.scoreCiLow * 100).toFixed(0)}-{(path.scoreCiHigh * 100).toFixed(0)}%
                  <InfoTip text="Credible interval from per-edge evidence: narrow = trust the number, wide = treat it as a rough estimate." />
                </span>
              )}
            {path.confidenceLabel && (
              <span
                className={`flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${CONFIDENCE_TONE[path.confidenceLabel] ?? CONFIDENCE_TONE.medium}`}
                title="How much to trust this score, from how its edge weights were derived: evidence-backed (KEV/EPSS/runtime) hops raise it, severity/assumed hops lower it. An honest read of a modeled number, not false precision."
              >
                ● {path.confidenceLabel} confidence
              </span>
            )}
            {path.correlatedHops &&
              path.scoreUpperBound != null &&
              path.scoreUpperBound - path.score > 0.05 && (
                <span
                  className="flex items-center gap-1 rounded-md border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-300"
                  title="The exploit score multiplies the hops as if they were independent. Two or more hops here rest on the same basis (a shared cause), so the product is a lower bound - if they're correlated the real exploitability could be as high as the weakest hop. The true value lies in this band."
                >
                  ↑ up to {(path.scoreUpperBound * 100).toFixed(0)}% if correlated
                </span>
              )}
          </div>
        </div>

        {path.profileScores && path.profileScores.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted">
              by attacker profile
              <InfoTip text="The exploit score multiplies the hops as if independent. Conditioning on a latent attacker capability (commodity / criminal / APT) makes that honest within a profile, and marginalizing reintroduces the correlation the bare product drops - a path trivial for an APT can be out of reach for a commodity actor. Each chip is that class's end-to-end success probability ∏ p(e|c); 'blended' is the threat-model-weighted average Σ P(c)·∏ p(e|c)." />
            </span>
            {path.profileScores.map((p) => {
              const tone =
                p.profile === "apt"
                  ? "border-red-300 bg-red-50 text-red-700 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-300"
                  : p.profile === "criminal"
                    ? "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-300"
                    : "border-edge bg-slate-500/10 text-slate-600";
              const label = p.profile === "apt" ? "APT" : p.profile.charAt(0).toUpperCase() + p.profile.slice(1);
              return (
                <span
                  key={p.profile}
                  className={`rounded-md border px-1.5 py-0.5 text-[11px] font-medium tabular-nums ${tone}`}
                  title={`Threat-model prior ${(p.prior * 100).toFixed(0)}%`}
                >
                  {label} {(p.score * 100).toFixed(0)}%
                </span>
              );
            })}
            {path.mixtureScore != null && (
              <span
                className="text-[10px] tabular-nums text-muted"
                title="Threat-model-weighted average across profiles - the correlation-aware counterpart to the naive exploit score."
              >
                blended {(path.mixtureScore * 100).toFixed(0)}%
              </span>
            )}
          </div>
        )}

        {hasStatus && (
          <div className="flex flex-wrap items-center gap-1.5">
            {path.runtimeConfirmed && (
              <Badge tone="danger" icon={<ZapIcon className="h-3.5 w-3.5" />} className="text-[11px] font-bold" title="Runtime-confirmed by Falco - this path is being exercised right now.">
                ACTIVELY EXPLOITED
              </Badge>
            )}
            {path.openForSeconds != null && (
              <Badge tone="neutral" title="How long this path has been continuously open (since first observed). Persistence, not just existence, is what you triage on.">
                open {humanDuration(path.openForSeconds)}
              </Badge>
            )}
            {path.reopens != null && path.reopens > 0 && (
              <Badge tone="warn" title="This path resolved and then came back - a regression, likely reintroduced by a deploy.">
                ⟳ reopened {path.reopens}×
              </Badge>
            )}
            {path.suppressed && <Badge tone="neutral">suppressed</Badge>}
            {path.validation && (
              <Badge
                tone={VALIDATION_META[path.validation.outcome].tone}
                title={`Red-team/BAS verdict from ${path.validation.source}${path.validation.evidence ? ` - ${path.validation.evidence}` : ""}. Feeds the precision/recall metric.`}
              >
                {VALIDATION_META[path.validation.outcome].label} · {path.validation.source}
              </Badge>
            )}
          </div>
        )}

        {/* Action toolbar - Investigate (left) vs Decide (right). */}
        <div className="flex flex-wrap items-center gap-2 border-t border-edge pt-3.5">
          {onShowInGraph && (
            <Button variant="secondary" onClick={onShowInGraph}>
              Show in graph →
            </Button>
          )}
          <span className="mx-auto" />
          <ValidationControl path={path} onChanged={onTriaged} />
          <RemediationPRControl path={path} />
          {aiEnabled && <AiExplainControl path={path} />}
          <TriageControl path={path} onTriaged={onTriaged} />
          <TicketControl path={path} onChanged={onTriaged} />
        </div>
      </header>

      {/* ── Kill chain ───────────────────────────────────────────────── */}
      <section className="rounded-xl border border-edge bg-panel shadow-card p-5">
        <h3 className="mb-3 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-widest text-muted">
          Kill chain
          <InfoTip text="The attacker’s step-by-step route, mapped to MITRE ATT&CK. Each arrow is one hop with its traversal probability (p) and technique; chips flag exposure, crown jewels, live alerts, known-exploited CVEs and how each weight was derived. Hover a hop to run a what-if cut." />
        </h3>

        {whatIf && (
          <div className="mb-3 rounded-lg border border-accent/30 bg-accent/[0.06] px-3.5 py-2.5 text-[12px] text-slate-700">
            <div className="font-medium text-slate-800">
              What-if · cut <span className="font-mono text-[11px]">{whatIf.step.edgeType}</span> ({nameOf(whatIf.step.from)} → {nameOf(whatIf.step.to)})
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-slate-600">
              <span>
                Account compromise{" "}
                <span className="font-semibold tabular-nums text-slate-800">{(whatIf.result.beforeRisk.anyCompromiseProbability * 100).toFixed(1)}%</span> →{" "}
                <span className={`font-semibold tabular-nums ${whatIf.result.riskReduction > 0.0005 ? "text-emerald-700" : "text-slate-800"}`}>
                  {(whatIf.result.afterRisk.anyCompromiseProbability * 100).toFixed(1)}%
                </span>
              </span>
              <span className="text-slate-400">·</span>
              <span>
                {whatIf.result.riskReduction > 0.0005 ? (
                  <span className="text-emerald-700">↓ {(whatIf.result.riskReduction * 100).toFixed(1)} pts removed</span>
                ) : (
                  <span className="text-amber-700">no global drop - other paths still reach a jewel</span>
                )}
              </span>
              <span className="text-slate-400">·</span>
              <span>
                {whatIf.result.after.length} attack path{whatIf.result.after.length === 1 ? "" : "s"} remain
              </span>
            </div>
          </div>
        )}

        <ol className="flex flex-col">
          {path.nodes.map((node, i) => (
            <li key={node.id}>
              <div className="flex items-center gap-3">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-edge bg-ink text-slate-500">
                  <AssetIcon label={node.label} className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-slate-800">{node.name}</span>
                    <NodeBadges node={node} />
                  </div>
                  <div className="text-[11px] text-muted">{node.label}</div>
                </div>
              </div>
              {i < path.steps.length && (
                <div className="group/step my-1 ml-4 flex items-center gap-2 border-l border-dashed border-edge py-1.5 pl-5">
                  <span className="rounded bg-slate-500/10 px-2 py-0.5 font-mono text-[10px] text-slate-500">{path.steps[i].edgeType}</span>
                  <span className="text-[10px] tabular-nums text-slate-400">p = {path.steps[i].probability.toFixed(2)}</span>
                  {path.steps[i].attack && (
                    <a
                      href={path.steps[i].attack!.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent transition hover:bg-accent/20"
                      title={`MITRE ATT&CK ${path.steps[i].attack!.id} - ${path.steps[i].attack!.name} · tactic: ${path.steps[i].attack!.tactic}`}
                    >
                      <CrosshairIcon className="h-3 w-3" />
                      {path.steps[i].attack!.id} · {path.steps[i].attack!.tactic}
                    </a>
                  )}
                  {path.steps[i].weightBasis && <BasisChip basis={path.steps[i].weightBasis!} />}
                  {path.steps[i].resolutionConfidence != null && path.steps[i].resolutionConfidence! < 1 && (
                    <Badge
                      tone="warn"
                      dashed
                      icon={<AlertTriangleIcon className="h-3 w-3" />}
                      title={`This hop was inferred by the resolver (${path.steps[i].resolutionMethod} match), not asserted by a tool. Confidence ${(path.steps[i].resolutionConfidence! * 100).toFixed(0)}% - verify this link; the probability above is already discounted for it.`}
                    >
                      heuristic join · {(path.steps[i].resolutionConfidence! * 100).toFixed(0)}%
                    </Badge>
                  )}
                  <button
                    onClick={() => simulateCut(path.steps[i])}
                    disabled={cutting !== null}
                    className="ml-1 inline-flex items-center gap-1 rounded border border-edge px-1.5 py-0.5 text-[10px] text-slate-400 opacity-0 transition hover:border-accent/50 hover:text-accent focus-visible:opacity-100 group-hover/step:opacity-100 disabled:opacity-40"
                    title="Simulate cutting this edge and see the residual risk"
                  >
                    {cutting === `${path.steps[i].from}->${path.steps[i].to}` ? (
                      "…"
                    ) : (
                      <>
                        <ScissorsIcon className="h-3 w-3" /> what-if
                      </>
                    )}
                  </button>
                </div>
              )}
            </li>
          ))}
        </ol>
      </section>

      {/* ── Remediations ─────────────────────────────────────────────── */}
      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-muted">
          Suggested remediation{path.remediations.length === 1 ? "" : "s"}
          {path.remediations.length > 0 && ` (${path.remediations.length})`}
        </h3>
        {path.remediations.length === 0 ? (
          <div className="rounded-xl border border-edge bg-panel shadow-card p-4 text-xs text-muted">
            No generated remediation for this path shape yet.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {path.remediations.map((r, i) => (
              <ArtifactCard key={`${r.filename}-${i}`} r={r} />
            ))}
          </div>
        )}
      </section>

      {/* ── Detection-as-code ────────────────────────────────────────── */}
      {path.detections.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-muted">Detection-as-code ({path.detections.length})</h3>
          <p className="mb-2 text-xs text-muted">
            Remediation cuts the path; these Falco/Sigma rules <span className="font-medium">watch</span> it - deploy them to catch
            exploitation of the exposed workload.
          </p>
          <div className="flex flex-col gap-3">
            {path.detections.map((d, i) => (
              <ArtifactCard key={`${d.filename}-${i}`} r={d} tone="indigo" />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
