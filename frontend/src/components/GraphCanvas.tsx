import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { Edge, Node } from "../api/client";

// Node fill by ontology category.
function labelColor(label: string): string {
  switch (label) {
    case "VirtualMachine":
    case "Container":
    case "VPC":
    case "LoadBalancer":
      return "#3b82f6"; // infrastructure — blue
    case "Database":
    case "Bucket":
      return "#a855f7"; // data stores — violet
    case "Repository":
    case "Image":
    case "Package":
    case "Library":
      return "#14b8a6"; // code/app — teal
    case "User":
    case "IAM_Role":
    case "ServiceAccount":
      return "#f59e0b"; // identity — amber
    default:
      return "#ef4444"; // security (CVE/Weakness/Misconfig/Secret) — red
  }
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

  // (Re)build the graph whenever the topology changes.
  useEffect(() => {
    if (!containerRef.current) return;

    const elements: ElementDefinition[] = [
      ...nodes.map((n) => ({
        data: {
          id: n.id,
          label: `${n.name || n.id}${n.runtimeAlert ? " ⚡" : ""}`,
          color: labelColor(n.label),
          badge: n.internetExposed ? "🌐" : n.crownJewel ? "💎" : "",
        },
      })),
      ...edges.map((e) => ({
        data: {
          id: `${e.from}->${e.to}`,
          source: e.from,
          target: e.to,
          label: `${e.type} (${e.probability.toFixed(2)})`,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#e5edff",
            "font-size": 9,
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 26,
            height: 26,
            "border-width": 2,
            "border-color": "#0b1020",
          },
        },
        {
          selector: "edge",
          style: {
            label: "data(label)",
            "font-size": 7,
            color: "#7d8bb0",
            width: 1.5,
            "line-color": "#33406a",
            "target-arrow-color": "#33406a",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: "node.hl",
          style: { "border-color": "#f43f5e", "border-width": 4, width: 32, height: 32 },
        },
        {
          selector: "edge.hl",
          style: { "line-color": "#f43f5e", "target-arrow-color": "#f43f5e", width: 3.5, "font-size": 9, color: "#fda4af" },
        },
        {
          selector: ".faded",
          style: { opacity: 0.18 },
        },
      ],
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.3, padding: 24 },
    });

    if (onSelectNode) {
      cy.on("tap", "node", (evt) => onSelectNode(evt.target.id()));
    }
    cyRef.current = cy;
    return () => cy.destroy();
  }, [nodes, edges, onSelectNode]);

  // Apply highlight classes when the selected path changes.
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
  }, [highlightNodes, highlightEdges]);

  return <div ref={containerRef} className="h-full w-full rounded-lg bg-panel" />;
}
