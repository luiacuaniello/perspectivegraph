import { useEffect, useRef, useState } from "react";
import { searchAssets, type SearchHit } from "../api/client";
import { labelColor } from "./graphColors";
import { SearchIcon } from "./icons";

const DEBOUNCE_MS = 300;

export default function SearchView({ enabled = true }: { enabled?: boolean }) {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    window.clearTimeout(timer.current);
    const q = query.trim();
    if (!q) {
      setHits(null);
      setError(null);
      setBusy(false);
      return;
    }
    setBusy(true);
    timer.current = window.setTimeout(() => {
      searchAssets(q)
        .then((h) => {
          setHits(h);
          setError(null);
        })
        .catch((e) => setError(String(e.message ?? e)))
        .finally(() => setBusy(false));
    }, DEBOUNCE_MS);
    return () => window.clearTimeout(timer.current);
  }, [query]);

  const maxScore = hits?.length ? Math.max(...hits.map((h) => h.score)) : 1;

  // Distinguish “feature off” from “no matches”: with OpenSearch disabled, an
  // empty result is NOT a real negative, so say so plainly instead of pretending.
  if (!enabled) {
    return (
      <div className="grid h-full place-items-center">
        <div className="max-w-lg rounded-2xl border border-edge bg-panel shadow-card p-7 text-center">
          <div className="mx-auto mb-3 grid h-11 w-11 place-items-center rounded-xl bg-slate-500/10 text-slate-400">
            <SearchIcon className="h-5 w-5" />
          </div>
          <h2 className="text-base font-semibold text-slate-900">Full-text search is off</h2>
          <p className="mx-auto mt-2 max-w-md text-[13px] leading-relaxed text-slate-600">
            Search needs the optional <span className="font-medium text-slate-800">OpenSearch</span> index, which
            isn’t configured. Everything else works without it.
          </p>
          <div className="mt-4 rounded-xl bg-ink px-4 py-3 text-left text-[12px]">
            <div className="mb-1 text-[11px] font-medium text-muted">Enable it</div>
            <code className="block font-mono text-teal-700">
              docker compose --profile app --profile search up -d --build
            </code>
            <code className="mt-1 block font-mono text-slate-500">
              # set OPENSEARCH_URL=http://opensearch:9200, then re-seed (make seed)
            </code>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <div className="relative">
        <span className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500">
          <svg
            viewBox="0 0 20 20"
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.7}
            strokeLinecap="round"
          >
            <circle cx="9" cy="9" r="5.5" />
            <path d="M13.5 13.5 L17 17" />
          </svg>
        </span>
        <input
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search assets & findings - try “log4j”, “PII”, “secret”, a CVE id…"
          className="w-full rounded-xl border border-edge bg-panel shadow-card py-3 pl-10 pr-4 text-sm text-slate-800 placeholder:text-slate-400 outline-hidden transition focus:border-accent focus:ring-2 focus:ring-accent/15"
        />
        {busy && (
          <span className="absolute right-4 top-1/2 -translate-y-1/2 text-[11px] text-slate-500">
            searching…
          </span>
        )}
      </div>

      {error && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-xs text-amber-700">
          Search failed: {error}
        </div>
      )}

      {!error && hits !== null && (
        <div className="min-h-0 flex-1 overflow-y-auto pr-1">
          {hits.length === 0 ? (
            <div className="rounded-xl border border-edge bg-panel shadow-card p-5 text-sm text-slate-500">
              No results for <span className="text-slate-700">“{query.trim()}”</span>.
              <p className="mt-2 text-xs text-slate-500">
                Full-text search needs the optional OpenSearch index: start it with{" "}
                <code className="text-teal-700">make up-search</code>, run the backend with{" "}
                <code className="text-teal-700">OPENSEARCH_URL=http://localhost:9200</code> and re-ingest
                (<code className="text-teal-700">make seed</code>) so assets get indexed.
              </p>
            </div>
          ) : (
            <ul className="flex flex-col gap-2">
              {hits.map((h) => (
                <li
                  key={h.id}
                  className="flex items-center gap-3 rounded-xl border border-edge bg-panel shadow-card px-4 py-3"
                >
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-full"
                    style={{ background: labelColor(h.label) }}
                  />
                  <span className="w-28 shrink-0 text-[11px] uppercase tracking-wide text-slate-500">
                    {h.label}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm text-slate-800">{h.name}</span>
                  <span className="flex w-32 shrink-0 items-center gap-2">
                    <span className="h-1 flex-1 overflow-hidden rounded-full bg-ink">
                      <span
                        className="block h-full rounded-full bg-teal-400/70"
                        style={{ width: `${Math.max(8, (h.score / maxScore) * 100)}%` }}
                      />
                    </span>
                    <span className="text-[10px] tabular-nums text-slate-500">{h.score.toFixed(2)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {!error && hits === null && (
        <div className="grid flex-1 place-items-center text-sm text-slate-400">
          Type to search the indexed environment.
        </div>
      )}
    </div>
  );
}
