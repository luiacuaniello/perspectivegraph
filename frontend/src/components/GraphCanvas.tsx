import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJson } from "cytoscape";
import type { Edge, Node } from "../api/client";
import { useTheme, type Theme } from "../theme";

// Category of an ontology label: drives both fill color and node shape, so the
// canvas reads like an architecture diagram (shapes survive where color alone
// would not - projectors, color-blindness, print).
type Category = "infra" | "data" | "code" | "identity" | "finding";

function category(label: string): Category {
  switch (label) {
    case "VirtualMachine":
    case "Container":
    case "VPC":
    case "LoadBalancer":
      return "infra";
    case "Database":
    case "Bucket":
      return "data";
    case "Repository":
    case "Image":
    case "Package":
    case "Library":
      return "code";
    case "User":
    case "IAM_Role":
    case "ServiceAccount":
      return "identity";
    default:
      return "finding"; // CVE / Weakness / Misconfiguration / Secret
  }
}

// Cool, saturated-enough corporate tones that read on a light canvas.
const CATEGORY_STYLE: Record<Category, { color: string; shape: string; name: string }> = {
  infra: { color: "#4f78b3", shape: "round-rectangle", name: "Infrastructure" },
  data: { color: "#c79a3a", shape: "barrel", name: "Data store" },
  code: { color: "#2f9488", shape: "hexagon", name: "Code & artifacts" },
  identity: { color: "#7e8ca0", shape: "ellipse", name: "Identity" },
  finding: { color: "#d2554f", shape: "round-diamond", name: "Finding" },
};

// Shared with the search view's result chips.
export function labelColor(label: string): string {
  return CATEGORY_STYLE[category(label)].color;
}

// Small SVG glyph matching each category's node shape, for the legend.
function ShapeGlyph({ cat }: { cat: Category }) {
  const { color, shape } = CATEGORY_STYLE[cat];
  return (
    <svg viewBox="0 0 14 14" className="h-3 w-3 shrink-0" fill={color} aria-hidden="true">
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

// Theme-dependent canvas colors: the structural tones (labels, the ring around a
// node, resting edges) must flip with light/dark, while the category fills and
// the seed/jewel/KEV/highlight accent rings read on both and stay fixed.
interface GraphPalette {
  nodeLabel: string;
  nodeBorder: string; // ring color = the canvas/panel bg, so fills read cleanly
  edgeLabel: string;
  edgeLine: string;
  hlNodeLabel: string;
}

function graphPalette(theme: Theme): GraphPalette {
  return theme === "dark"
    ? { nodeLabel: "#c2ccdc", nodeBorder: "#171c26", edgeLabel: "#97a5ba", edgeLine: "#3a465a", hlNodeLabel: "#edf1f8" }
    : { nodeLabel: "#33404f", nodeBorder: "#ffffff", edgeLabel: "#5b6675", edgeLine: "#c2cad6", hlNodeLabel: "#1f2430" };
}

function buildStyle(p: GraphPalette): StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        shape: "data(shape)" as never,
        "background-color": "data(color)",
        "background-opacity": 0.95,
        label: "data(label)",
        color: p.nodeLabel,
        "font-size": 10,
        "font-weight": 600,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-wrap": "wrap",
        "text-max-width": "120",
        // A halo in the canvas colour keeps labels legible over the dot grid and
        // any edges that pass beneath them.
        "text-outline-width": 2.5,
        "text-outline-color": p.nodeBorder,
        "text-outline-opacity": 1,
        "min-zoomed-font-size": 7, // hide labels when zoomed far out → less clutter
        width: 30,
        height: 30,
        "border-width": 2,
        "border-color": p.nodeBorder, // clean ring separating the fill from the canvas
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
        width: 1.4,
        "line-color": p.edgeLine,
        opacity: 0.6, // resting structure recedes so highlighted paths pop
        "target-arrow-color": p.edgeLine,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.85,
        "curve-style": "bezier",
        "text-rotation": "autorotate",
      },
    },
    {
      // Actively exploited at runtime (Falco) - a warm "live" ring. The seed /
      // jewel / KEV rings below take precedence for nodes that are also those.
      selector: "node.runtime",
      style: { "border-color": "#e0683a", "border-width": 3 },
    },
    {
      // Where attacks start: a green ring marks internet-exposed entry points.
      selector: "node.seed",
      style: { "border-color": "#2f9e5f", "border-width": 3 },
    },
    {
      // Where attacks aim: a gold ring marks crown jewels (the targets).
      selector: "node.jewel",
      style: { "border-color": "#caa53a", "border-width": 3.5 },
    },
    {
      // KEV - exploited in the wild: a warm amber ring even when not on the
      // selected path, so it stands out at a glance.
      selector: "node.kev",
      style: { "border-color": "#e0a03a", "border-width": 3 },
    },
    {
      selector: "node.hl",
      style: {
        "border-color": "#d23f38",
        "border-width": 3.5,
        width: 38,
        height: 38,
        color: p.hlNodeLabel,
        "font-size": 11,
        "font-weight": 700,
        // A soft red glow makes the highlighted chain unmistakable.
        "underlay-color": "#d23f38",
        "underlay-opacity": 0.18,
        "underlay-padding": 8,
        "z-index": 10,
      },
    },
    {
      selector: "edge.hl",
      style: {
        "line-color": "#d23f38",
        "target-arrow-color": "#d23f38",
        width: 3.2,
        opacity: 1,
        "text-opacity": 1,
        "font-size": 9,
        "font-weight": 600 as never,
        color: "#d2554f",
        "z-index": 9,
      },
    },
    {
      selector: ".faded",
      style: { opacity: 0.12 },
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
  themeRef.current = theme;

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
      style: buildStyle(graphPalette(themeRef.current)),
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
    cy.style(buildStyle(graphPalette(theme)));
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
        className="graph-canvas-bg h-full w-full rounded-xl border border-edge bg-panel shadow-card"
      />

      {/* Zoom / fit controls */}
      <div className="absolute right-3 top-3 flex flex-col overflow-hidden rounded-lg border border-edge bg-panel/95 shadow-card backdrop-blur">
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
      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-col gap-1.5 rounded-lg border border-edge bg-panel/90 px-3 py-2 shadow-card backdrop-blur">
        {(Object.keys(CATEGORY_STYLE) as Category[]).map((cat) => (
          <span key={cat} className="flex items-center gap-2 text-[10px] text-slate-500">
            <ShapeGlyph cat={cat} />
            {CATEGORY_STYLE[cat].name}
          </span>
        ))}
        <span className="mt-1.5 flex flex-col gap-1 border-t border-edge pt-1.5 text-[10px] text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="grid h-3 w-3 place-items-center rounded-full border-2" style={{ borderColor: "#2f9e5f" }} />
            entry (internet-exposed)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="grid h-3 w-3 place-items-center rounded-full border-2" style={{ borderColor: "#caa53a" }} />
            target (crown jewel)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="grid h-3 w-3 place-items-center rounded-full border-2" style={{ borderColor: "#e0683a" }} />
            runtime-confirmed (live)
          </span>
        </span>
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
