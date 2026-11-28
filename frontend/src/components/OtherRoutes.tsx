import { useState } from "react";
import { fetchOtherRoutes, type AttackPath, type RouteSketch } from "../api/client";
import Button from "./ui/Button";
import InfoTip from "./InfoTip";
import { NodeName } from "./routeChannelViews";

// "If I close this route, is the asset still reachable?" The list answers it for the best
// route from each entry; the engine's k-shortest search answers it for the asset, by
// listing the next most probable routes to it, whichever entry they start from.
//
// Asked for, not loaded with the detail: it is one of the server's heavy analyses, and the
// detail changes on every j or k. Ranked by probability rather than priority, and with
// suppressed routes included, as the engine returns them - so the page says both. A route
// that is also on the list opens there; one that is not (a second-best way between the
// same two assets, say) is shown and not linked, because the list has no page for it.

const ASK = 6; // the route on screen, usually first, and five others

interface Props {
  path: AttackPath;
  // Whether a route id is on the dashboard's list, where it can be opened.
  isListed: (id: string) => boolean;
  onOpenPath: (id: string) => void;
}

type State = { kind: "idle" } | { kind: "asking" } | { kind: "answered"; routes: RouteSketch[] } | { kind: "failed"; message: string };

export default function OtherRoutes({ path, isListed, onOpenPath }: Props) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const target = path.nodes[path.nodes.length - 1];
  if (!target) return null;

  const ask = () => {
    setState({ kind: "asking" });
    fetchOtherRoutes(target.id, ASK)
      .then((routes) => setState({ kind: "answered", routes: routes.filter((r) => r.id !== path.id).slice(0, ASK - 1) }))
      .catch((e) => setState({ kind: "failed", message: e instanceof Error ? e.message : String(e) }));
  };

  return (
    <section aria-labelledby={`other-routes-${path.id}`} className="rounded-xl border border-edge bg-panel p-5 shadow-card">
      <h3 id={`other-routes-${path.id}`} className="flex items-center gap-1.5 text-xs font-semibold text-muted">
        Other routes to <NodeName name={target.name} className="text-slate-700" />
        <InfoTip text="The engine's most probable routes to the same asset, from any entry. They are ranked by probability, not by priority, and include routes taken off the board. A fix on this route may close some of them too: the what-if on a hop says which." />
      </h3>

      {state.kind === "idle" && (
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2">
          <p className="text-[13px] text-slate-600">Closing this route may not close the way in.</p>
          <Button variant="secondary" size="sm" onClick={ask}>
            Look for other routes
          </Button>
        </div>
      )}
      {state.kind === "asking" && <p className="mt-2 text-[13px] text-muted">Looking for other routes…</p>}
      {state.kind === "failed" && (
        <p role="alert" className="mt-2 text-[13px] text-amber-800">
          Could not look for other routes: {state.message}
        </p>
      )}
      {state.kind === "answered" &&
        (state.routes.length === 0 ? (
          <p className="mt-2 text-[13px] text-slate-700">
            The engine finds no other route to it: this is the only way in it knows of.
          </p>
        ) : (
          <ol className="mt-2 flex flex-col gap-1">
            {state.routes.map((r) => (
              <li key={r.id}>
                <OtherRoute route={r} listed={isListed(r.id)} onOpen={() => onOpenPath(r.id)} />
              </li>
            ))}
          </ol>
        ))}
    </section>
  );
}

function OtherRoute({ route: r, listed, onOpen }: { route: RouteSketch; listed: boolean; onOpen: () => void }) {
  const entry = r.nodes[0];
  const hops = r.steps.length;
  const body = (
    <>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] text-slate-700">
          from <NodeName name={entry?.name} /> · {hops} {hops === 1 ? "hop" : "hops"}
        </span>
        <span className="mt-0.5 block text-[12px] text-muted">
          {r.nodes
            .slice(1, -1)
            .map((n) => n.name)
            .join(" → ") || "straight to it"}
          {r.suppressed ? " · taken off the board" : ""}
          {!listed ? " · not on the list" : ""}
        </span>
      </span>
      <span className="shrink-0 text-[13px] font-semibold tabular-nums text-slate-800" title="How likely the whole route is.">
        {Math.round(r.score * 100)}%
      </span>
    </>
  );
  return listed ? (
    <button type="button" onClick={onOpen} className="flex w-full items-start gap-3 rounded-lg px-2 py-1.5 text-left transition hover:bg-panel-2/60">
      {body}
    </button>
  ) : (
    <div className="flex items-start gap-3 px-2 py-1.5">{body}</div>
  );
}
