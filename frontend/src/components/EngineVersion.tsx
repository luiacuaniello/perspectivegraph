import { useEffect, useState } from "react";
import { fetchEngine } from "../api/client";

// Only a published build has release notes to link to; a local build reports a module
// version, a commit or "dev", and is shown as it is.
const RELEASE_TAG = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const RELEASES = "https://github.com/luiacuaniello/perspectivegraph/releases/tag/";

// The foot of every page says which release the engine runs, so anyone looking at an
// instance - a public demo, a colleague's deployment - can tell without a shell in its
// pods. It is the engine's version, not the dashboard's: the engine computes every number
// on the page. Asked again whenever the backend comes back, since that is when an upgrade
// shows; an engine too old to answer, or one that cannot be reached, gets no line at all
// rather than a wrong one.
export default function EngineVersion({ live }: { live: boolean }) {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    if (!live) return;
    let current = true;
    fetchEngine()
      .then((engine) => {
        if (current) setVersion(engine.version);
      })
      .catch(() => {
        if (current) setVersion(null);
      });
    return () => {
      current = false;
    };
  }, [live]);

  if (!version) return null;
  return (
    <footer className="shrink-0 px-4 pb-3 text-[12px] text-muted sm:px-8">
      PerspectiveGraph engine{" "}
      {RELEASE_TAG.test(version) ? (
        <a
          href={RELEASES + version}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={`Release notes for ${version}`}
          className="tabular-nums underline-offset-2 hover:text-slate-700 hover:underline"
        >
          {version}
        </a>
      ) : (
        <span className="tabular-nums">{version}</span>
      )}
    </footer>
  );
}
