import { useEffect, useState, type FormEvent } from "react";
import { fetchVerdict, humanDuration, type AttackPath, type CommitRoute, type CommitVerdict } from "../api/client";
import { validSha, validSlug, type CommitRef } from "../routeHash";
import Badge from "./ui/Badge";
import Button from "./ui/Button";
import { NodeName, TargetIcon } from "./routeChannelViews";

// One commit's answer from the merge gate: the page a pull request's check links to. A red
// check whose Details opened the dashboard's front page left the developer to find their
// change among every route in the estate; this names the commit and the routes it is
// answerable for.
//
// It says what the check says. Under the default rule (PR_ATTRIBUTION=diff) a commit
// answers for the routes it opened or made likelier, not for every route through an asset
// it touched, so the routes that were there before it are listed apart and said not to
// count. And it keeps the gate's third state: a commit the engine never saw is unknown,
// which is not clean.

interface Props {
  commit: CommitRef | null;
  // The last analysis pass: a new one is when the answer can change, so it is asked again.
  analyzedAt: string | null;
  onLookup: (commit: CommitRef | null) => void;
  onOpenPath: (id: string) => void;
}

type Outcome = "unknown" | "clean" | "blocked";

export default function CommitVerdictView({ commit, analyzedAt, onLookup, onOpenPath }: Props) {
  const [answer, setAnswer] = useState<{ key: string; verdict: CommitVerdict } | null>(null);
  const [failure, setFailure] = useState<{ key: string; message: string } | null>(null);
  const slug = commit?.slug ?? "";
  const sha = commit?.sha ?? "";
  const key = commit ? `${slug}@${sha}` : "";

  // Asked again on every analysis pass (analyzedAt), so a developer who opened the page
  // before the scan landed sees the answer arrive.
  useEffect(() => {
    if (!slug || !sha) return;
    const asked = `${slug}@${sha}`;
    let current = true;
    fetchVerdict(slug, sha)
      .then((verdict) => {
        if (!current) return;
        if (verdict) {
          setAnswer({ key: asked, verdict });
          setFailure(null);
        } else {
          setFailure({ key: asked, message: "the engine returned no verdict" });
        }
      })
      .catch((e) => {
        if (current) setFailure({ key: asked, message: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      current = false;
    };
  }, [slug, sha, analyzedAt]);

  if (!commit) return <LookupForm onLookup={onLookup} />;

  // An answer about another commit is not this commit's, even for the render before the
  // new one arrives.
  const verdict = answer?.key === key ? answer.verdict : null;
  const error = failure?.key === key ? failure.message : null;

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      {verdict ? (
        <VerdictCard verdict={verdict} onOpenPath={onOpenPath} />
      ) : error ? (
        <div role="alert" className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-[13px] text-amber-800">
          The engine could not answer for {commit.slug} at {shortSha(commit.sha)}: {error}
        </div>
      ) : (
        <div className="rounded-xl border border-edge bg-panel p-5 text-[13px] text-muted shadow-card">
          Asking the engine about {commit.slug} at {shortSha(commit.sha)}…
        </div>
      )}
      <div>
        <Button variant="ghost" size="sm" onClick={() => onLookup(null)}>
          Check another commit
        </Button>
      </div>
    </div>
  );
}

function VerdictCard({ verdict: v, onOpenPath }: { verdict: CommitVerdict; onOpenPath: (id: string) => void }) {
  const standing = new Map((v.routes ?? []).map((r) => [r.pathId, r]));
  const counted = v.paths.filter((p) => standing.get(p.id)?.counts);
  const already = v.paths.filter((p) => standing.get(p.id) && !standing.get(p.id)?.counts);
  const perCommit = v.attribution === "commit";
  const outcome: Outcome = !v.analysed ? "unknown" : counted.length > 0 ? "blocked" : "clean";

  return (
    <>
      <section aria-labelledby="verdict-commit" className="rounded-xl border border-edge bg-panel p-5 shadow-card">
        <p className="text-[12px] text-muted">Commit</p>
        <h2 id="verdict-commit" className="mt-0.5 break-all font-mono text-[15px] text-slate-900">
          {v.slug} <span className="text-slate-500">at</span> {shortSha(v.sha)}
        </h2>
        <div className="mt-3 flex flex-wrap items-start gap-x-2.5 gap-y-1.5">
          <OutcomeBadge outcome={outcome} />
          <p className="min-w-0 flex-1 text-[14px] leading-snug text-slate-700">
            {summary(outcome, counted.length, already.length, perCommit)}
          </p>
        </div>
        <p className="mt-3 text-[12px] text-muted">
          {v.analysedAt ? (
            <time dateTime={v.analysedAt} title={v.analysedAt}>
              Last analysis {ago(v.analysedAt)}
            </time>
          ) : (
            "No analysis has run yet."
          )}
          {outcome === "unknown" &&
            " If the scan went out after that, wait for the next one: this page asks again when it runs."}
        </p>
      </section>

      {counted.length > 0 && (
        <RouteSection
          title={perCommit ? "Routes through this commit" : "Counted against this commit"}
          paths={counted}
          standing={standing}
          perCommit={perCommit}
          onOpenPath={onOpenPath}
        />
      )}
      {already.length > 0 && (
        <RouteSection
          title="Already there before it"
          note="They run through an asset this commit changed, but they were there before it arrived, so they don't count against it."
          paths={already}
          standing={standing}
          perCommit={perCommit}
          onOpenPath={onOpenPath}
        />
      )}
    </>
  );
}

function summary(outcome: Outcome, counted: number, already: number, perCommit: boolean): string {
  const routes = (n: number) => `${n} critical ${n === 1 ? "route" : "routes"}`;
  if (outcome === "unknown") {
    return "Nothing from this commit has reached the engine, so the gate answers unknown and fails closed. Check that the scan was sent with this repository and this commit.";
  }
  if (outcome === "blocked") {
    return perCommit
      ? `${routes(counted)} ${counted === 1 ? "runs" : "run"} through this commit. Under the per-commit rule (PR_ATTRIBUTION=commit) every one of them counts.`
      : `${routes(counted)} opened or made likelier by this commit.`;
  }
  if (perCommit) return "No critical route runs through this commit.";
  const before =
    already === 1
      ? " 1 critical route that was already there runs through it; it doesn't count."
      : already > 1
        ? ` ${routes(already)} that were already there run through it; they don't count.`
        : "";
  return `No critical route opened or made likelier by this commit.${before}`;
}

function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  if (outcome === "blocked") return <Badge tone="danger">Blocked</Badge>;
  if (outcome === "clean") return <Badge tone="ok">Clean</Badge>;
  return <Badge tone="warn">Not analysed</Badge>;
}

function RouteSection({
  title,
  note,
  paths,
  standing,
  perCommit,
  onOpenPath,
}: {
  title: string;
  note?: string;
  paths: AttackPath[];
  standing: Map<string, CommitRoute>;
  perCommit: boolean;
  onOpenPath: (id: string) => void;
}) {
  return (
    <section className="rounded-xl border border-edge bg-panel p-4 shadow-card">
      <h3 className="text-[14px] font-semibold text-slate-900">
        {title} <span className="font-normal tabular-nums text-muted">({paths.length})</span>
      </h3>
      {note && <p className="mt-1 text-[12px] leading-snug text-muted">{note}</p>}
      <ul className="mt-2 flex flex-col gap-1">
        {paths.map((p) => (
          <li key={p.id}>
            <RouteRow path={p} change={changeLabel(standing.get(p.id), p, perCommit)} onOpen={() => onOpenPath(p.id)} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function RouteRow({ path: p, change, onOpen }: { path: AttackPath; change: string; onOpen: () => void }) {
  const entry = p.nodes[0];
  const target = p.nodes[p.nodes.length - 1];
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-full items-start gap-2.5 rounded-lg px-2 py-2 text-left transition hover:bg-panel-2/60"
    >
      <TargetIcon path={p} className="mt-[4px]" />
      <span className="min-w-0 flex-1">
        <NodeName name={target?.name} className="block break-words text-[13px] font-medium text-slate-800" />
        <span className="mt-0.5 block text-[12px] text-slate-600">
          {p.directAccess ? (
            "open to anyone · direct access"
          ) : (
            <>
              from <NodeName name={entry?.name} /> · {p.steps.length} {p.steps.length === 1 ? "hop" : "hops"}
            </>
          )}
        </span>
        {/* The route's standing with this commit, not its triage status: "New" beside "Was
            there before this commit" read as a contradiction. The paths view has the status. */}
        {change && <span className="mt-1 block text-[12px] text-muted">{change}</span>}
      </span>
      {p.priority != null && (
        <span className="shrink-0 text-right">
          <span className="block text-[15px] font-semibold leading-none tabular-nums text-slate-900">{p.priority.toFixed(0)}</span>
          <span className="mt-0.5 block text-[12px] font-semibold text-muted">{p.priorityLabel ?? "priority"}</span>
        </span>
      )}
    </button>
  );
}

function changeLabel(r: CommitRoute | undefined, p: AttackPath, perCommit: boolean): string {
  switch (r?.change) {
    case "introduced":
      return "Opened by this commit";
    case "worsened":
      return `Made likelier by this commit: ${pct(r.previousScore)} before, ${pct(p.score)} now`;
    case "later":
      return "Appeared through it after it arrived";
    case "recorded":
      return perCommit ? "Runs through it" : "Counted: the engine holds no estate from before this commit";
    case "preexisting":
      return "Was there before this commit";
    default:
      return "";
  }
}

function LookupForm({ onLookup }: { onLookup: (commit: CommitRef) => void }) {
  const [slug, setSlug] = useState("");
  const [sha, setSha] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const s = slug.trim();
    const c = sha.trim();
    if (!validSlug(s)) {
      setError("A repository is owner/name, the way the gate sends it.");
      return;
    }
    if (!validSha(c)) {
      setError("A commit is its SHA: 7 to 64 hexadecimal characters.");
      return;
    }
    setError(null);
    onLookup({ slug: s, sha: c });
  };

  return (
    <form onSubmit={submit} className="flex max-w-xl flex-col gap-3 rounded-xl border border-edge bg-panel p-5 shadow-card">
      <p className="text-[13px] leading-snug text-slate-700">
        A pull request's check links here with its commit filled in. To ask about a commit yourself, name it as the
        merge gate does.
      </p>
      <label className="flex flex-col gap-1 text-[12px] font-medium text-slate-700">
        Repository
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="owner/name"
          autoComplete="off"
          spellCheck={false}
          className="h-9 rounded-lg border border-edge bg-panel px-2.5 font-mono text-[13px] font-normal text-slate-900 outline-hidden focus:border-accent"
        />
      </label>
      <label className="flex flex-col gap-1 text-[12px] font-medium text-slate-700">
        Commit SHA
        <input
          value={sha}
          onChange={(e) => setSha(e.target.value)}
          placeholder="3f2a91c…"
          autoComplete="off"
          spellCheck={false}
          className="h-9 rounded-lg border border-edge bg-panel px-2.5 font-mono text-[13px] font-normal text-slate-900 outline-hidden focus:border-accent"
        />
      </label>
      {error && (
        <p role="alert" className="text-[12px] text-flag">
          {error}
        </p>
      )}
      <div>
        <Button type="submit" variant="primary" size="md">
          Show the verdict
        </Button>
      </div>
    </form>
  );
}

function shortSha(sha: string): string {
  return sha.length > 12 ? sha.slice(0, 12) : sha;
}

function pct(score: number): string {
  return `${Math.round(score * 100)}%`;
}

function ago(iso: string): string {
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!Number.isFinite(secs)) return "at an unknown time";
  return secs < 5 ? "just now" : `${humanDuration(Math.max(0, secs))} ago`;
}
