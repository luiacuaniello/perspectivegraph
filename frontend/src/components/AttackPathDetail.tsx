import { useId, useState } from "react";
import {
  aiExplain,
  type AIAnswer,
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
  LockIcon,
  ScissorsIcon,
  TicketIcon,
  ZapIcon,
} from "./icons";
import InfoTip from "./InfoTip";
import Button from "./ui/Button";
import { useReadOnly } from "../auth/readOnly";
import Badge from "./ui/Badge";
import { ModelAttribution } from "./ModelAttribution";
import { hopReason, hopVerb, pathSummary, typeName } from "./pathLanguage";

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
  "rounded-md border border-edge bg-panel px-2 py-1.5 text-[12px] text-slate-700 outline-hidden focus:border-accent";

// TriageControl is the suppression loop: record a triage decision (reason +
// accountable owner + optional expiry) that takes this path off the active board,
// un-suppress one already triaged, or show the in-force decision.
function TriageControl({ path, onTriaged }: { path: AttackPath; onTriaged?: () => void }) {
  const readOnly = useReadOnly();
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
          <Button variant="secondary" onClick={unsuppress} disabled={busy || !!readOnly} title={readOnly ?? undefined}>
            {busy ? "…" : "Un-suppress"}
          </Button>
        </div>
        {s.note && <div className="mt-1 italic text-slate-500">“{s.note}”</div>}
        {err && <div className="mt-1 text-flag">{err}</div>}
      </div>
    );
  }

  if (!open) {
    return (
      <Button
        variant="ghost"
        onClick={() => setOpen(true)}
        disabled={!!readOnly}
        title={readOnly ?? "Triage this path: accept the risk, mark a false positive, note a mitigating control or a duplicate"}
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
          <span className="text-[12px] text-slate-500">{REASONS.find((r) => r.value === reason)?.hint}</span>
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
      {err && <div className="mt-2 text-flag">{err}</div>}
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
  const readOnly = useReadOnly();
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
      <div className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[12px] font-medium text-emerald-700">
        <TicketIcon className="h-3.5 w-3.5" />
        <span>Ticketed · {path.ticket.owner}</span>
        {path.ticket.externalUrl && (
          <a href={path.ticket.externalUrl} target="_blank" rel="noreferrer" className="underline">
            open ↗
          </a>
        )}
        <Button variant="ghost" onClick={close} disabled={busy || !!readOnly} title={readOnly ?? undefined} className="text-emerald-700 hover:bg-emerald-500/10">
          {busy ? "…" : "close"}
        </Button>
        {err && <span className="text-flag">{err}</span>}
      </div>
    );
  }
  if (!open) {
    return (
      <Button variant="ghost" onClick={() => setOpen(true)} disabled={!!readOnly} icon={<TicketIcon className="h-3.5 w-3.5" />} title={readOnly ?? "Open an owned, tracked remediation ticket for this path"}>
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
      {err && <span className="text-[12px] text-flag">{err}</span>}
    </div>
  );
}

// AiExplainControl asks Claude to explain this path in plain English. Renders the
// button plus a full-width answer block that wraps onto its own line.
function AiExplainControl({ path }: { path: AttackPath }) {
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState<AIAnswer | null>(null);
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
      <Button variant="ghost" onClick={explain} disabled={busy} title="Explain this path in plain English with Claude">
        {busy ? "Explaining…" : text ? "Re-explain (AI)" : "Explain (AI)"}
      </Button>
      {err && <span className="text-[12px] text-flag">{err}</span>}
      {text && (
        <div className="basis-full rounded-lg border border-edge bg-ink px-3 py-2">
          <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-slate-700">{text.answer}</p>
          <ModelAttribution answer={text} />
        </div>
      )}
    </>
  );
}

// RemediationPRControl opens a pull request with this path's generated fix
// (branch + commit + PR). The backend needs a GitHub token; admin role when auth
// is on. Closes the loop: the fix arrives as a PR to review, not a copy-paste.
function RemediationPRControl({ path, primary = false }: { path: AttackPath; primary?: boolean }) {
  const readOnly = useReadOnly();
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (url) {
    return (
      <a
        href={url}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[12px] font-medium text-emerald-700 underline"
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
        variant={primary ? "primary" : "secondary"}
        size={primary ? "md" : "sm"}
        onClick={open}
        disabled={busy || !!readOnly}
        icon={<ScissorsIcon className="h-3.5 w-3.5" />}
        title={readOnly ?? "Open a pull request with the generated fix for this path (needs a GitHub token on the backend)"}
      >
        {busy ? "Opening PR…" : "Open fix PR"}
      </Button>
      {err && <span className="text-[12px] text-flag">{err}</span>}
    </span>
  );
}

const VALIDATION_OPTIONS: { value: ValidationOutcome; label: string }[] = [
  { value: "confirmed", label: "Confirmed - exploitable end-to-end" },
  { value: "refuted", label: "Refuted - not traversable (false positive)" },
  { value: "partial", label: "Partial - partially traversable" },
];

// ValidationControl records a red-team/BAS test result for this path - the
// evidence that turns a modeled path into a tested one (feeds precision/recall).
function ValidationControl({ path, onChanged }: { path: AttackPath; onChanged?: () => void }) {
  const readOnly = useReadOnly();
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
      <Button variant="ghost" onClick={() => setOpen(true)} disabled={!!readOnly} icon={<CheckIcon className="h-3.5 w-3.5" />} title={readOnly ?? "Record a red-team / BAS test result for this path (confirmed, refuted or partial)"}>
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
      {err && <div className="mt-2 text-flag">{err}</div>}
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
    ? `Inferred sensitive asset (${basis.replace("inferred:", "signal: ")}) - guessed from a sensitive-data signal, not an explicit tag. Verify the classification.`
    : classifiedJewel
      ? `Sensitive asset from a real data classifier (${basis.replace("classified:", "")}) - authoritative, not a name guess.`
      : "Sensitive asset - a high-value traversal target.";
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {node.internetExposed && (
        <Badge tone="info" icon={<GlobeIcon className="h-3 w-3" />}>
          internet-exposed
        </Badge>
      )}
      {node.crownJewel && (
        <Badge tone="warn" icon={<GemIcon className="h-3 w-3" />} title={jewelTitle}>
          sensitive asset{inferredJewel ? " (inferred)" : classifiedJewel ? " (classified)" : ""}
        </Badge>
      )}
      {node.account && (
        <Badge tone="neutral" title={`Cloud account ${node.account}. Identifiers like i-… and sg-… are unique only within an account, so this is what tells two same-named assets apart.`}>
          {node.account}
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

// PREVIEW_LINES is how much of a generated file shows before "Show all". The artifacts
// used to print in full, three of them one under the other, and made the page 2,600px tall
// - with long lines cut at the panel's edge and no sign there was more to the right.
const PREVIEW_LINES = 12;

function ArtifactCard({ r, tone = "emerald" }: { r: Artifact; tone?: "emerald" | "indigo" }) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const lines = r.content.split("\n");
  const long = lines.length > PREVIEW_LINES;
  const shown = expanded || !long ? r.content : lines.slice(0, PREVIEW_LINES).join("\n");
  const copy = () => {
    navigator.clipboard.writeText(r.content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([r.content], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = r.filename;
    a.click();
    URL.revokeObjectURL(url);
  };
  const badge = tone === "indigo" ? "bg-indigo-500/15 text-indigo-700" : "bg-emerald-500/15 text-emerald-700";

  return (
    <div className="overflow-hidden rounded-xl border border-edge bg-panel shadow-card">
      <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className={`shrink-0 rounded-sm px-2 py-0.5 text-[12px] font-semibold uppercase tracking-wide ${badge}`}>{r.kind}</span>
          <span className="truncate text-sm font-medium text-slate-800">{r.title}</span>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <Button variant="ghost" onClick={download} title={`Download ${r.filename}`}>
            download
          </Button>
          <Button variant="secondary" onClick={copy} icon={copied ? <CheckIcon className="h-3.5 w-3.5" /> : undefined}>
            {copied ? "copied" : "copy"}
          </Button>
        </div>
      </div>
      <div className="px-4 py-3">
        <p className="mb-2 text-[13px] leading-relaxed text-slate-600">{r.rationale}</p>
        <div className="mb-1 font-mono text-[12px] text-slate-500">{r.filename}</div>
        <div className="relative">
          <pre
            tabIndex={0}
            role="region"
            aria-label={`Generated file: ${r.filename}`}
            className="overflow-x-auto whitespace-pre rounded-lg bg-ink p-3 font-mono text-[12px] leading-relaxed text-slate-600"
          >
            {shown}
          </pre>
          {long && !expanded && (
            <div className="pointer-events-none absolute inset-x-0 bottom-0 h-10 rounded-b-lg bg-gradient-to-t from-ink to-transparent" />
          )}
        </div>
        {long && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="mt-1.5 text-[12px] font-medium text-accent hover:underline"
          >
            {expanded ? "Show less" : `Show all ${lines.length} lines`}
          </button>
        )}
      </div>
    </div>
  );
}

// Priority bands by WEIGHT, not by hue.
//
// These were a red / amber / grey ramp, which put severity back in the colour channel
// that now carries lifecycle state - the overload the redesign set out to remove. P1
// still reads first: it is the only one that inverts, and inversion is a stronger signal
// at a glance than a colour is.
const PRIORITY_TONE: Record<string, string> = {
  P1: "bg-slate-900 text-panel",
  P2: "bg-slate-200 text-slate-900",
  P3: "bg-slate-100 text-slate-600",
};

// BASIS_META maps a hop's weight provenance to a short label and whether it is
// observed evidence (green) or an estimate (grey). "assumed" read like an alarm about the
// attacker; it means the engine used its default weight for this kind of hop.
const BASIS_META: Record<string, { label: string; evidence: boolean }> = {
  kev: { label: "KEV", evidence: true },
  epss: { label: "EPSS", evidence: true },
  runtime: { label: "runtime", evidence: true },
  cvss: { label: "from CVSS", evidence: false },
  severity: { label: "from severity", evidence: false },
  heuristic: { label: "default weight", evidence: false },
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
          : "This hop's probability is an estimate - derived from CVSS or severity, or the engine's default for this kind of hop - not observed."
      }
    >
      {meta.label}
    </Badge>
  );
}

// Generic priority factors that say nothing about THIS path: every critical path ends at a
// sensitive asset, and a live alert has its own badge.
const QUIET_FACTORS = new Set(["sensitive asset target", "runtime-confirmed (active)"]);

type Tab = "fix" | "detect" | "evidence";

export default function AttackPathDetail({ path, onShowInGraph, onTriaged, aiEnabled }: Props) {
  const readOnly = useReadOnly();
  const entry = path.nodes[0];
  const target = path.nodes[path.nodes.length - 1];
  const [tab, setTab] = useState<Tab>("fix");
  const tabId = useId();

  // The accounts this route passes through, in order and de-duplicated. Empty or
  // single on an estate that ingests one account - which is why nothing below renders
  // there: the multi-account affordance costs a single-account user no screen space.
  const crossedAccounts = path.nodes.reduce<string[]>((acc, n) => {
    const a = n.account?.trim();
    if (a && acc[acc.length - 1] !== a && !acc.includes(a)) acc.push(a);
    return acc;
  }, []);

  // What-if: cut one edge of this path and show the residual quantified risk.
  const [whatIf, setWhatIf] = useState<{ step: Step; result: WhatIfResult } | null>(null);
  const [cutting, setCutting] = useState<string | null>(null);
  const nameOf = (id: string) => path.nodes.find((n) => n.id === id)?.name ?? id;
  const nodeOf = (id: string) => path.nodes.find((n) => n.id === id);

  const simulateCut = (step: Step) => {
    const key = `${step.from}->${step.to}`;
    setCutting(key);
    setWhatIf(null);
    runWhatIf([{ from: step.from, to: step.to, type: step.edgeType }])
      .then((result) => setWhatIf({ step, result }))
      .catch(() => setWhatIf(null))
      .finally(() => setCutting(null));
  };

  // The hop the first generated fix severs: where the reader should cut.
  const cut = path.remediations.find((r) => r.cut)?.cut ?? null;
  const isCut = (s: Step) => !!cut && cut.from === s.from && cut.to === s.to && cut.type === s.edgeType;

  const ciInforms =
    path.scoreCiLow != null && path.scoreCiHigh != null && path.scoreCiHigh - path.scoreCiLow > 0.02;
  const verdict = path.validation;
  // The same rule as the engine's re-banding and the list's status: a failed test does not
  // undo a runtime alert or an asset open to anyone.
  const conflict = (path.runtimeConfirmed || !!path.directAccess) && verdict?.outcome === "refuted";
  const factors = (path.priorityFactors ?? []).filter((f) => !QUIET_FACTORS.has(f));

  const tabs: { id: Tab; label: string }[] = [
    { id: "fix", label: `Fix${path.remediations.length ? ` (${path.remediations.length})` : ""}` },
    { id: "detect", label: `Detect${path.detections.length ? ` (${path.detections.length})` : ""}` },
    { id: "evidence", label: "Evidence" },
  ];
  const onTabKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === tab);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const to = tabs[(next + tabs.length) % tabs.length].id;
    setTab(to);
    document.getElementById(`${tabId}-tab-${to}`)?.focus();
  };

  return (
    <div className="flex flex-col gap-4">
      {/* ── Header: what the route is, how urgent, how likely, what to do ───────── */}
      <header className="flex flex-col gap-4 rounded-xl border border-edge bg-panel p-5 shadow-card">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-muted">
              Attack path ·{" "}
              {path.directAccess ? (
                <span title="The sensitive asset is open to anyone - a bucket anyone may read, a role any principal may assume - so no step stands in the way. Closing it is the fix.">
                  direct access
                </span>
              ) : (
                <>
                  {path.steps.length} step{path.steps.length === 1 ? "" : "s"}
                </>
              )}
              {crossedAccounts.length > 1 && (
                <>
                  {" · "}
                  <span
                    className="text-slate-900"
                    title={`This route does not stay in one account: it runs through ${crossedAccounts.join(" → ")}. A boundary an org chart treats as a wall is being crossed by the path.`}
                  >
                    crosses {crossedAccounts.length} accounts
                  </span>
                </>
              )}
            </div>
            <h2 className="mt-1 flex flex-wrap items-baseline gap-x-2 text-lg font-semibold text-slate-900">
              {path.directAccess ? (
                <span>{target?.name}</span>
              ) : (
                <>
                  <span>{entry?.name}</span>
                  <span className="text-muted">→</span>
                  <span>{target?.name}</span>
                </>
              )}
            </h2>
            <p className="mt-1.5 max-w-prose text-[13px] leading-relaxed text-slate-600">{pathSummary(path)}</p>
          </div>

          {/* Two numbers, each named for the question it answers: how urgent (priority,
              what the queue is ordered by) and how likely (one probability, with its range;
              the other readings of it live under Evidence). */}
          <div className="flex shrink-0 items-start gap-6 sm:text-right">
            {path.priority != null && (
              <div title="Composite triage priority [0,100]: exploitability and trust in it, runtime/KEV corroboration, target sensitivity and entry blast radius - and a fact about the route (a live alert, open access, a red-team verdict) lifts it to P1.">
                <div className="text-[12px] text-muted">Priority</div>
                <div className="mt-1 flex items-center gap-2 text-3xl font-semibold leading-none tabular-nums text-slate-900 sm:justify-end">
                  {path.priorityLabel && (
                    <span
                      className={`rounded-md px-1.5 py-1 text-base font-bold leading-none ${PRIORITY_TONE[path.priorityLabel] ?? PRIORITY_TONE.P3}`}
                    >
                      {path.priorityLabel}
                    </span>
                  )}
                  <span>{path.priority.toFixed(0)}</span>
                </div>
                <div className="mt-1 text-[12px] text-muted">of 100 · fix first</div>
              </div>
            )}
            <div>
              <div className="flex items-center gap-1 text-[12px] text-muted sm:justify-end">
                Exploit probability
                <InfoTip text="How likely an attacker completes the whole route: each hop's probability, multiplied. The range is the 90% credible interval from how much evidence backs each hop; how it varies by attacker is under Evidence." />
              </div>
              <div
                className={`mt-1 font-semibold leading-none tabular-nums ${
                  path.priority != null ? "text-2xl text-slate-700" : "text-3xl text-slate-900"
                }`}
              >
                {(path.score * 100).toFixed(0)}%
              </div>
              <div className="mt-1 text-[12px] tabular-nums text-muted">
                {path.directAccess
                  ? "nothing to exploit"
                  : ciInforms
                    ? `range ${(path.scoreCiLow! * 100).toFixed(0)}–${(path.scoreCiHigh! * 100).toFixed(0)}%`
                    : ""}
              </div>
            </div>
          </div>
        </div>

        {/* Why it is in its band - a fact when a fact put it there, else the factors. */}
        {(path.priorityReason || factors.length > 0) && (
          <div className="rounded-lg bg-ink/60 px-3 py-2 text-[13px] leading-relaxed text-slate-600">
            <span className="font-semibold text-slate-800">
              Why {path.priorityLabel ?? "this priority"}:{" "}
            </span>
            {path.priorityReason ? `${path.priorityReason}.` : factors.join(" · ")}
          </div>
        )}

        {/* Status: what is known about the route right now. */}
        {(path.runtimeConfirmed || verdict || path.openForSeconds != null || (path.reopens ?? 0) > 0 || path.suppressed) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {path.runtimeConfirmed && (
              <Badge
                tone="danger"
                icon={<ZapIcon className="h-3.5 w-3.5" />}
                className="font-semibold"
                title="A runtime sensor (Falco) fired on a workload of this route: it is being exercised, not only predicted."
              >
                Runtime alert on this route
              </Badge>
            )}
            {verdict && (
              <Badge
                tone={verdict.outcome === "partial" ? "warn" : "neutral"}
                icon={verdict.outcome === "confirmed" ? <CheckIcon className="h-3 w-3" /> : undefined}
                title={`Red-team/BAS verdict from ${verdict.source}${verdict.evidence ? ` - ${verdict.evidence}` : ""}. Feeds the accuracy metrics.`}
              >
                {VALIDATION_LABEL[verdict.outcome]} {verdict.source}
              </Badge>
            )}
            {conflict && (
              <Badge
                tone="warn"
                icon={<AlertTriangleIcon className="h-3 w-3" />}
                title={
                  path.runtimeConfirmed
                    ? `A runtime alert fired on this route, but ${verdict!.source} could not walk it. The alert may be that test itself - check before closing either.`
                    : `The asset is open to anyone, but ${verdict!.source} could not reach it. Check the exposure before trusting the test.`
                }
              >
                Evidence conflicts
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
          </div>
        )}

        {/* Actions: one primary - apply the fix - and the rest quieter, but on screen: on a
            read-only instance they are how a visitor learns what the product does. */}
        <div className="flex flex-wrap items-center gap-2 border-t border-edge pt-3.5">
          <RemediationPRControl path={path} primary={path.remediations.length > 0} />
          <span className="mx-auto" />
          <ValidationControl path={path} onChanged={onTriaged} />
          {aiEnabled && <AiExplainControl path={path} />}
          <TriageControl path={path} onTriaged={onTriaged} />
          <TicketControl path={path} onChanged={onTriaged} />
          {readOnly && (
            <span className="flex w-full items-center justify-end gap-1.5 text-[12px] text-muted">
              <LockIcon className="h-3.5 w-3.5" />
              {readOnly}
            </span>
          )}
        </div>
      </header>

      {/* ── Kill chain ─────────────────────────────────────────────────────────── */}
      <section className="rounded-xl border border-edge bg-panel p-5 shadow-card">
        <h3 className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-muted">
          How the attack works
          <InfoTip text="The route step by step: what each asset does to the next, the chance of that hop, and the MITRE ATT&CK technique where the hop is something an attacker does. Scissors mark where the generated fix cuts; any hop can be simulated cut (what-if)." />
        </h3>

        {whatIf && (
          <div className="mb-3 rounded-lg border border-accent/30 bg-accent/6 px-3.5 py-2.5 text-[12px] text-slate-700">
            <div className="font-medium text-slate-800">
              What-if · cut “{hopVerb(whatIf.step.edgeType)}” ({nameOf(whatIf.step.from)} → {nameOf(whatIf.step.to)})
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-slate-600">
              <span>
                Account compromise{" "}
                <span className="font-semibold tabular-nums text-slate-800">{(whatIf.result.beforeRisk.anyCompromiseProbability * 100).toFixed(1)}%</span> →{" "}
                <span className={`font-semibold tabular-nums ${whatIf.result.riskReduction > 0.0005 ? "text-emerald-700" : "text-slate-800"}`}>
                  {(whatIf.result.afterRisk.anyCompromiseProbability * 100).toFixed(1)}%
                </span>
              </span>
              <span className="text-slate-500">·</span>
              <span>
                {whatIf.result.riskReduction > 0.0005 ? (
                  <span className="text-emerald-700">↓ {(whatIf.result.riskReduction * 100).toFixed(1)} pts removed</span>
                ) : (whatIf.result.expectedReduction ?? 0) > 0.0005 ? (
                  <span
                    className="text-emerald-700"
                    title="Account compromise does not move because another sensitive asset stays compromised either way; this cut still protects the ones it closes."
                  >
                    ↓ {whatIf.result.expectedReduction!.toFixed(2)} sensitive assets compromised on average
                  </span>
                ) : (
                  <span className="text-amber-700">no drop - other paths still reach the same sensitive assets</span>
                )}
              </span>
              <span className="text-slate-500">·</span>
              <span>
                {whatIf.result.after.length} attack path{whatIf.result.after.length === 1 ? "" : "s"} remain
              </span>
            </div>
          </div>
        )}

        <ol className="flex flex-col">
          {path.nodes.map((node, i) => {
            const step = i < path.steps.length ? path.steps[i] : null;
            const reason = step ? hopReason(step, node, nodeOf(step.to)) : null;
            const cutHere = step ? isCut(step) : false;
            return (
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
                    <div className="text-[12px] text-muted">{typeName(node.label)}</div>
                  </div>
                </div>
                {step && (
                  // Wraps: a hop carries up to six chips, and on a phone the ones past the
                  // edge were clipped - the ATT&CK technique and the weight basis among them.
                  <div
                    className={`group/step my-1 ml-4 flex flex-col gap-1 border-l py-1.5 pl-5 ${
                      cutHere ? "border-solid border-accent" : "border-dashed border-edge"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="text-[13px] text-slate-700" title={step.edgeType}>
                        {hopVerb(step.edgeType)}
                      </span>
                      <span
                        className="text-[12px] font-semibold tabular-nums text-slate-600"
                        title="The chance an attacker completes this hop."
                      >
                        {(step.probability * 100).toFixed(0)}%
                      </span>
                      {step.attack && (
                        <a
                          href={step.attack.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded-sm bg-accent/10 px-1.5 py-0.5 text-[12px] font-medium text-accent transition hover:bg-accent/20"
                          title={`MITRE ATT&CK ${step.attack.id} - ${step.attack.name} · tactic: ${step.attack.tactic}`}
                        >
                          <CrosshairIcon className="h-3 w-3" />
                          {step.attack.id} · {step.attack.tactic}
                        </a>
                      )}
                      {step.weightBasis && <BasisChip basis={step.weightBasis} />}
                      {step.resolutionConfidence != null && step.resolutionConfidence < 1 && (
                        <Badge
                          tone="warn"
                          dashed
                          icon={<AlertTriangleIcon className="h-3 w-3" />}
                          title={`Linked by the resolver (${step.resolutionMethod} match), not asserted by a tool - ${(step.resolutionConfidence * 100).toFixed(0)}% confidence. Verify this link; the probability already accounts for it.`}
                        >
                          inferred link · {(step.resolutionConfidence * 100).toFixed(0)}%
                        </Badge>
                      )}
                      {cutHere && (
                        <Badge tone="accent" icon={<ScissorsIcon className="h-3 w-3" />} title="The generated fix severs this hop.">
                          the fix cuts here
                        </Badge>
                      )}
                      {/* Revealed on hover where there is a hover. A touch screen has none, so
                          there the cut was invisible and untappable: always show it. */}
                      <button
                        onClick={() => simulateCut(step)}
                        disabled={cutting !== null}
                        className="ml-1 inline-flex items-center gap-1 rounded-sm border border-edge px-1.5 py-0.5 text-[12px] text-slate-500 opacity-0 transition hover:border-accent/50 hover:text-accent focus-visible:opacity-100 group-hover/step:opacity-100 pointer-coarse:opacity-100 disabled:opacity-40"
                        title="Simulate cutting this hop and see the residual risk"
                      >
                        {cutting === `${step.from}->${step.to}` ? (
                          "…"
                        ) : (
                          <>
                            <ScissorsIcon className="h-3 w-3" /> what-if
                          </>
                        )}
                      </button>
                    </div>
                    {reason && <div className="text-[12px] text-muted">because {reason}</div>}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      </section>

      {/* ── Fix / Detect / Evidence ────────────────────────────────────────────── */}
      <section className="rounded-xl border border-edge bg-panel shadow-card">
        <div className="flex items-center gap-1 border-b border-edge px-3">
          {/* The tablist holds the tabs and nothing else: with the graph button inside it,
              axe failed every detail view (aria-required-children), which the 1.25 audit
              caught. Arrows, Home and End move between tabs and only the selected one is in
              the Tab order - the keyboard contract a screen reader announces for a tablist. */}
          <div role="tablist" aria-label="Path details" className="flex items-center gap-1" onKeyDown={onTabKey}>
            {tabs.map((t) => (
              <button
                key={t.id}
                role="tab"
                id={`${tabId}-tab-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`${tabId}-panel-${t.id}`}
                tabIndex={tab === t.id ? 0 : -1}
                onClick={() => setTab(t.id)}
                className={`-mb-px border-b-2 px-3 py-2.5 text-[13px] font-medium transition ${
                  tab === t.id ? "border-accent text-slate-900" : "border-transparent text-muted hover:text-slate-700"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <span className="mx-auto" />
          {onShowInGraph && (
            <Button variant="ghost" onClick={onShowInGraph}>
              Show in graph →
            </Button>
          )}
        </div>

        {/* Every panel stays in the document, hidden when not selected: the tab pattern, and
            what keeps the evidence findable by a screen reader's search. */}
        <div role="tabpanel" id={`${tabId}-panel-fix`} aria-labelledby={`${tabId}-tab-fix`} hidden={tab !== "fix"} className="p-4">
          {path.remediations.length === 0 ? (
            <div className="text-[13px] text-muted">No generated fix for this path shape yet.</div>
          ) : (
            <div className="flex flex-col gap-3">
              {path.remediations.map((r, i) => (
                <ArtifactCard key={`${r.filename}-${i}`} r={r} />
              ))}
            </div>
          )}
        </div>

        <div role="tabpanel" id={`${tabId}-panel-detect`} aria-labelledby={`${tabId}-tab-detect`} hidden={tab !== "detect"} className="p-4">
          {path.detections.length === 0 ? (
            <div className="text-[13px] text-muted">No generated detection for this path shape yet.</div>
          ) : (
            <>
              {/* The same detection in different formats, not several things to deploy. */}
              <p className="mb-3 text-[13px] leading-relaxed text-slate-600">
                The fix <span className="font-medium">cuts</span> the path; these rules <span className="font-medium">watch</span> it
                until it is cut. They are the <span className="font-medium">same</span> detection for different stacks - deploy the
                one that matches what you run.
              </p>
              <div className="flex flex-col gap-3">
                {path.detections.map((d, i) => (
                  <ArtifactCard key={`${d.filename}-${i}`} r={d} tone="indigo" />
                ))}
              </div>
            </>
          )}
        </div>

        <div role="tabpanel" id={`${tabId}-panel-evidence`} aria-labelledby={`${tabId}-tab-evidence`} hidden={tab !== "evidence"} className="flex flex-col gap-4 p-4 text-[13px]">
          {(path.priorityFactors ?? []).length > 0 && (
            <div>
              <div className="mb-1.5 text-[12px] font-semibold text-muted">What the priority weighs</div>
              <div className="flex flex-wrap gap-1.5">
                {(path.priorityFactors ?? []).map((f) => (
                  <span key={f} className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[12px] text-slate-600">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div>
            <div className="mb-1.5 text-[12px] font-semibold text-muted">How sure the probability is</div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] tabular-nums text-muted">
              {ciInforms ? (
                <span title="90% credible interval from per-edge evidence (epistemic): tight = trust the number, wide = a rough estimate. Distinct from the correlation ceiling.">
                  90% CI {(path.scoreCiLow! * 100).toFixed(0)}-{(path.scoreCiHigh! * 100).toFixed(0)}%
                  {path.confidenceLabel ? ` · ${path.confidenceLabel} confidence` : ""}
                </span>
              ) : (
                path.confidenceLabel && <span>{path.confidenceLabel} confidence</span>
              )}
              {path.correlatedHops && path.scoreUpperBound != null && path.scoreUpperBound - path.score > 0.05 && (
                <span title="The probability multiplies hops as if independent; if two or more share a cause, the real value could be as high as the weakest hop (the Fréchet ceiling).">
                  up to {(path.scoreUpperBound * 100).toFixed(0)}% if correlated
                </span>
              )}
            </div>
          </div>
          {path.profileScores && path.profileScores.length > 0 && (
            <div>
              <div className="mb-1.5 flex items-center gap-1 text-[12px] font-semibold text-muted">
                by attacker profile
                <InfoTip text="Success probability per attacker class (commodity / criminal / APT); 'blended' averages them by threat-model prior. Easy for an APT can be hard for a commodity actor." />
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {path.profileScores.map((p) => {
                  const label = p.profile === "apt" ? "APT" : p.profile.charAt(0).toUpperCase() + p.profile.slice(1);
                  return (
                    <span
                      key={p.profile}
                      className="rounded-md border border-edge px-2 py-0.5 text-[12px] tabular-nums text-muted"
                      title={`Threat-model prior ${(p.prior * 100).toFixed(0)}%`}
                    >
                      {label} <span className="font-medium text-slate-900">{(p.score * 100).toFixed(0)}%</span>
                    </span>
                  );
                })}
                {path.mixtureScore != null && (
                  <span
                    className="text-[12px] tabular-nums text-muted"
                    title="Threat-model-weighted average across profiles - the correlation-aware counterpart to the plain product."
                  >
                    blended {(path.mixtureScore * 100).toFixed(0)}%
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

// VALIDATION_LABEL is how a verdict reads next to its source: "Proven by caldera" - the
// list's word for a route a tester walked (routeChannels).
const VALIDATION_LABEL: Record<ValidationOutcome, string> = {
  confirmed: "Proven by",
  refuted: "Refuted by",
  partial: "Partly walked by",
  missed: "Missed by",
};
