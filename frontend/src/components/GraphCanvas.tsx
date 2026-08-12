import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJson } from "cytoscape";
import type { Edge, Node } from "../api/client";
import { useTheme } from "../theme";
import { category, CATEGORY_STYLE, labelColor, type Category } from "./graphColors";


// Small SVG glyph matching each category's node shape, for the legend.
//
// Outlined in the same neutral the canvas draws a node in, not filled with a category
// colour: the nodes stopped being tinted by category (colour is reserved for entry,
// jewel, runtime and cut), so a coloured swatch here would name a colour the map no
// longer draws. The SHAPE is the category, and the legend now says exactly that.
function ShapeGlyph({ cat }: { cat: Category }) {
  const { shape } = CATEGORY_STYLE[cat];
  return (
    <svg
      viewBox="0 0 14 14"
      className="h-3 w-3 shrink-0"
      fill="#1a2430"
      stroke="#3d4c5c"
      strokeWidth="1.4"
      aria-hidden="true"
    >
      {shape === "round-rectangle" && <rect x="1.5" y="3" width="11" height="8" rx="2" />}
      {shape === "barrel" && (
        <path d="M2.5 4.2C2.5 2.6 4.5 2 7 2s4.5.6 4.5 2.2v5.6c0 1.6-2 2.2-4.5 2.2s-4.5-.6-4.5-2.2Z" />
      )}
      {shape === "hexagon" && <polygon points="7,1.5 12.3,4.3 12.3,9.7 7,12.5 1.7,9.7 1.7,4.3" />}
      {shape === "ellipse" && <circle cx="7" cy="7" r="5.5" />}
      {shape === "round-diamond" && <rect x="3" y="3" width="8" height="8" rx="1.5" transform="rotate(45 7 7)" />}
    </svg>
  );
}

// Canvas colors. No longer theme-dependent: the structural tones (labels, the ring around a
// node, resting edges) must flip with light/dark, while the category fills and
// the seed/jewel/KEV/highlight accent rings read on both and stay fixed.
interface GraphPalette {
  nodeLabel: string;
  nodeBorder: string; // ring color = the canvas/panel bg, so fills read cleanly
  edgeLabel: string;
  edgeLine: string;
}

// The map keeps its own night, in both themes.
//
// Everywhere else the product moved to a paper ground; the graph did not follow. On a
// light canvas these four semantic colours have to be muddied to hold contrast against
// white, and this is the one surface where colour carries meaning that cannot be
// recovered from shape or position - so it gets a dark, inset surface instead, the way a
// chart is inset into a printed report. One palette, no theme branch: the map looks the
// same to two people comparing screens.
function graphPalette(): GraphPalette {
  return {
    nodeLabel: "#dfe7ef",
    nodeBorder: "#0a0f14",
    edgeLabel: "#7b8896",
    edgeLine: "#3a4756",
  };
}

function buildStyle(p: GraphPalette): StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        shape: "data(shape)" as never,
        // Direction C's node: a translucent fill with the category colour as its OUTLINE,
        // rather than a solid puck. On the dark canvas the fill reads as volume and the
        // stroke carries the identity, so a node looks like a thing occupying space in a
        // map instead of a dot on a chart - and the semantic rings below (entry, jewel,
        // runtime) sit on the same stroke without fighting a saturated fill underneath.
        // Neutral by default. Category still drives the SHAPE, but no longer the
        // colour: when every node was tinted by what it is, the four colours that mean
        // something - entry, jewel, runtime, cut - had to compete with a canvas already
        // full of hues. A hop is now a quiet slate box, and colour appears only where it
        // carries a fact.
        "background-color": "#1a2430",
        "background-opacity": 1,
        "border-color": "#3d4c5c",
        label: "data(label)",
        color: p.nodeLabel,
        // Monospace, like the rest of the map's chrome: these are identifiers - image
        // digests, role names, CIDRs - and a proportional face makes them read as prose.
        "font-family": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        "font-size": 9.5,
        "font-weight": 400,
        "text-valign": "bottom",
        "text-margin-y": 7,
        "text-wrap": "wrap",
        "text-max-width": "120",
        // No halo. It existed to lift labels off the dot grid; the grid is gone, and the
        // outline was thickening every glyph into a smudge at this size.
        "text-outline-width": 0,
        "min-zoomed-font-size": 7, // hide labels when zoomed far out → less clutter
        width: 30,
        height: 30,
        "border-width": 1.6,
        "transition-property": "width height border-width",
        "transition-duration": 150 as never,
      },
    },
    {
      // Edge labels stay hidden until a path is highlighted: the resting
      // canvas reads as a clean architecture diagram.
      selector: "edge",
      style: {
        label: "data(label)",
        "text-opacity": 0,
        "font-size": 8,
        color: p.edgeLabel,
        "text-outline-width": 2,
        "text-outline-color": p.nodeBorder,
        "text-outline-opacity": 1,
        width: 1.1,
        "line-color": p.edgeLine,
        opacity: 0.75, // thin and quiet, but readable: the mockup's hairline
        "target-arrow-color": p.edgeLine,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.85,
        "curve-style": "bezier",
        "text-rotation": "autorotate",
      },
    },
    // ── The map's four colours, one meaning each ────────────────────────────────
    // Order matters: Cytoscape applies later rules over earlier ones, so this reads
    // runtime < entry < jewel - a crown jewel that is also an entry point shows as a
    // jewel, which is the fact that decides what you do about it.
    {
      // Being walked right now (Falco). The product's one red, same as the flag in the
      // lists - so "this is live" looks identical wherever you meet it.
      selector: "node.runtime",
      style: { "border-color": "#e2685f", "border-width": 2.4, "background-color": "#2a1c1c" },
    },
    {
      // Where an attack starts: internet-exposed.
      selector: "node.seed",
      style: { "border-color": "#35c5e8", "border-width": 2.4, "background-color": "#12303c" },
    },
    {
      // Where it aims. The heaviest ring on the canvas: the jewel is the only node whose
      // loss is the thing being prevented.
      selector: "node.jewel",
      style: {
        "border-color": "#e3a33a",
        "border-width": 2.6,
        "background-color": "#2b2213",
        // The jewel is the only node whose label is coloured: it names the thing whose
        // loss is what all of this exists to prevent.
        color: "#e3c48a",
      },
    },
    {
      // Known exploited in the wild. Not a jewel and not live, but not theoretical
      // either - it keeps the red, at a lighter weight than an active runtime hit.
      selector: "node.kev",
      style: { "border-color": "#e2685f", "border-width": 1.8 },
    },
    // The route under inspection is marked by LIGHT, not by hue.
    //
    // It used to be drawn in red - the same red that means "being walked in runtime" -
    // so selecting a dormant path made it look live. Selection is not a severity: it
    // gets brightness and size, which leaves all four semantic colours free to keep
    // meaning what they mean even inside the highlighted chain.
    {
      // Selection adds SIZE and a glow. It deliberately sets neither border-color nor
      // label colour: these rules apply after the semantic ones, so a white ring here
      // repainted every node on the route you were inspecting - the crown jewel lost its
      // gold at exactly the moment you were looking at it. Selection now says "this one",
      // and the four colours keep saying what they mean underneath it.
      selector: "node.hl",
      style: {
        "border-width": 3,
        width: 38,
        height: 38,
        "font-size": 10.5,
        "font-weight": 600,
        "underlay-color": "#ffffff",
        "underlay-opacity": 0.07,
        "underlay-padding": 7,
        "z-index": 10,
      },
    },
    {
      selector: "edge.hl",
      style: {
        "line-color": "#c8d4e0",
        "target-arrow-color": "#c8d4e0",
        width: 2.6,
        opacity: 1,
        "text-opacity": 1,
        "font-size": 9,
        "font-weight": 600 as never,
        color: "#c8d4e0",
        "z-index": 9,
      },
    },
    {
      selector: ".faded",
      style: { opacity: 0.22 },
    },
  ];
}

interface Props {
  nodes: Node[];
  edges: Edge[];
  highlightNodes: Set<string>;
  highlightEdges: Set<string>; // keys: `${from}->${to}`
  onSelectNode?: (id: string) => void;
}

export default function GraphCanvas({ nodes, edges, highlightNodes, highlightEdges, onSelectNode }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const sigRef = useRef<string>("");
  // Bumped on every rebuild so the highlight effect re-applies to the new instance.
  const [cyVersion, setCyVersion] = useState(0);
  // The graph rebuilds only on topology change, so read the theme through a ref
  // to colour a fresh build, and restyle in place (no relayout) when it toggles.
  const { theme } = useTheme();
  const themeRef = useRef(theme);
  // Written in an effect, not during render. A ref write during render is discarded or
  // applied out of order under concurrent rendering and runs twice in StrictMode, so
  // the value a later effect reads is not guaranteed to be the one this render saw.
  // useRef's initial value already makes the first build correct; this only has to keep
  // up with later toggles, and the rebuild effect it feeds runs on topology changes,
  // which are always after this has settled.
  useEffect(() => {
    themeRef.current = theme;
  }, [theme]);

  // (Re)build the graph only when the topology actually changes - the dashboard
  // polls every few seconds with fresh arrays, and rebuilding would reset the
  // user's pan/zoom and re-run the layout.
  useEffect(() => {
    if (!containerRef.current) return;

    const signature = JSON.stringify([
      nodes.map((n) => [n.id, n.name, n.label, n.internetExposed, n.crownJewel, n.runtimeAlert]),
      edges.map((e) => [e.from, e.to, e.type, e.probability]),
    ]);
    if (signature === sigRef.current && cyRef.current && !cyRef.current.destroyed()) return;
    sigRef.current = signature;

    const nodeIds = new Set(nodes.map((n) => n.id));
    const elements: ElementDefinition[] = [
      ...nodes.map((n) => ({
        data: {
          // The node's plain name; entry / crown-jewel / KEV / live status is shown
          // by the border ring (see the legend), not by glyphs in the label.
          id: n.id,
          label: n.name || n.id,
          color: labelColor(n.label),
          shape: CATEGORY_STYLE[category(n.label)].shape,
        },
        classes: [
          n.kev ? "kev" : "",
          n.internetExposed ? "seed" : "",
          n.crownJewel ? "jewel" : "",
          n.runtimeAlert ? "runtime" : "",
        ]
          .filter(Boolean)
          .join(" "),
      })),
      // Skip edges whose endpoints are missing: cytoscape throws on dangling
      // edges and a single bad one would blank the whole canvas.
      ...edges
        .filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to))
        .map((e) => ({
          data: {
            id: `${e.from}->${e.to}`,
            source: e.from,
            target: e.to,
            // Lead with the MITRE ATT&CK technique when this hop maps to one, so a
            // highlighted path reads as a kill chain (T1190 · EXPOSES (0.90)).
            label: `${e.attack?.id ? e.attack.id + " · " : ""}${e.type} (${e.probability.toFixed(2)})`,
          },
        })),
    ];

    cyRef.current?.destroy();
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: buildStyle(graphPalette()),
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.55, padding: 36, avoidOverlap: true, grid: false },
    });

    if (onSelectNode) {
      cy.on("tap", "node", (evt) => onSelectNode(evt.target.id()));
    }
    cyRef.current = cy;
    setCyVersion((v) => v + 1);
  }, [nodes, edges, onSelectNode]);

  // Destroy the instance only on unmount (and reset the cache so a remount -
  // including React StrictMode's dev double-mount - rebuilds from scratch).
  useEffect(
    () => () => {
      cyRef.current?.destroy();
      cyRef.current = null;
      sigRef.current = "";
    },
    [],
  );

  // Re-skin the existing instance when the theme toggles - no rebuild/relayout,
  // so the user's pan/zoom and the current highlight survive the swap.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    cy.style(buildStyle(graphPalette()));
  }, [theme, cyVersion]);

  // Tracks the last-fitted selection so we only re-center when it actually
  // changes (not on every background data refresh).
  const fitSigRef = useRef<string>("");

  // Apply highlight classes when the selected path (or the instance) changes,
  // then pan/zoom to frame the highlighted chain so it isn't lost off-screen.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const dim = highlightNodes.size > 0;
    cy.batch(() => {
      cy.elements().removeClass("hl faded");
      if (dim) cy.elements().addClass("faded");
      cy.nodes().forEach((n) => {
        if (highlightNodes.has(n.id())) n.removeClass("faded").addClass("hl");
      });
      cy.edges().forEach((e) => {
        if (highlightEdges.has(e.id())) e.removeClass("faded").addClass("hl");
      });
    });

    const sig = [...highlightNodes].sort().join("|");
    if (dim && sig !== fitSigRef.current) {
      const hl = cy.nodes().filter((n) => highlightNodes.has(n.id()));
      if (hl.length > 0) {
        cy.animate({ fit: { eles: hl, padding: 70 } }, { duration: 350, easing: "ease-out" });
      }
    }
    fitSigRef.current = sig;
  }, [highlightNodes, highlightEdges, cyVersion]);

  // Zoom/fit controls - a graph without an obvious "reset view" traps users who
  // pan/scroll off-canvas. Animated so the change is legible.
  const zoomBy = (factor: number) => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    const level = Math.min(2.5, Math.max(0.1, cy.zoom() * factor));
    cy.animate({ zoom: { level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 150 });
  };
  const fitAll = () => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    cy.animate({ fit: { eles: cy.elements(), padding: 50 } }, { duration: 250, easing: "ease-out" });
  };

  return (
    <div className="relative h-full w-full">
      <div
        ref={containerRef}
        className="graph-canvas-bg h-full w-full rounded-xl border border-[#1c2632] bg-[#0a0f14] shadow-card"
      />

      {/* Zoom / fit controls */}
      <div className="absolute right-3 top-3 flex flex-col overflow-hidden rounded-lg border border-[#1c2632] bg-[#101821]/95 text-[#dfe7ef] shadow-card backdrop-blur-sm">
        <GraphControl onClick={() => zoomBy(1.25)} title="Zoom in" label="Zoom in">
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round">
            <path d="M10 5v10M5 10h10" />
          </svg>
        </GraphControl>
        <GraphControl onClick={() => zoomBy(0.8)} title="Zoom out" label="Zoom out" className="border-t border-edge">
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round">
            <path d="M5 10h10" />
          </svg>
        </GraphControl>
        <GraphControl onClick={fitAll} title="Fit to screen" label="Fit to screen" className="border-t border-edge">
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
            <path d="M7 3H4a1 1 0 0 0-1 1v3M13 3h3a1 1 0 0 1 1 1v3M7 17H4a1 1 0 0 1-1-1v-3M13 17h3a1 1 0 0 0 1-1v-3" />
          </svg>
        </GraphControl>
      </div>
      <div className="pointer-events-none absolute bottom-3 left-3 rounded-lg border border-[#1c2632] bg-[#101821]/92 px-2.5 py-2 text-[10px] text-[#7b8896] shadow-card backdrop-blur-sm">
        <div className="grid grid-cols-2 gap-x-3 gap-y-1">
          {(Object.keys(CATEGORY_STYLE) as Category[]).map((cat) => (
            <span key={cat} className="flex items-center gap-1.5">
              <ShapeGlyph cat={cat} />
              {CATEGORY_STYLE[cat].name}
            </span>
          ))}
        </div>
        {/* The rings, in the order they override each other on the canvas. A legend that
            names a colour the canvas no longer draws is worse than no legend. */}
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 border-t border-[#1c2632] pt-1.5">
          <span className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#35c5e8" }} />
            entry
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#e3a33a" }} />
            sensitive asset
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full border-2" style={{ borderColor: "#e2685f" }} />
            runtime
          </span>
        </div>
      </div>
    </div>
  );
}

function GraphControl({
  onClick,
  title,
  label,
  children,
  className = "",
}: {
  onClick: () => void;
  title: string;
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={label}
      className={`grid h-8 w-8 place-items-center text-slate-500 transition hover:bg-ink hover:text-accent ${className}`}
    >
      {children}
    </button>
  );
}
