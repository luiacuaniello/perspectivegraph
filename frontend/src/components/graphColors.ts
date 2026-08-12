// Category colours + shapes for ontology labels, shared by the graph canvas and the
// search-result chips. Kept in its own module (no Cytoscape import) so the search view
// can use `labelColor` WITHOUT pulling the heavy graph canvas - which is what lets
// GraphCanvas be code-split and load only when the Graph view is opened.

// Category of an ontology label: drives both fill color and node shape, so the canvas
// reads like an architecture diagram (shapes survive where color alone would not -
// projectors, color-blindness, print).
export type Category = "infra" | "data" | "code" | "identity" | "finding";

export function category(label: string): Category {
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

// Tuned for the graph's own dark surface (see graphPalette): the canvas is inset and
// night-dark in both themes, so these no longer have to survive a white background.
//
// The SHAPE is the primary encoding and the colour is the reinforcement, not the other
// way round - the same asset reads correctly on a projector, in print, and to a reader
// who cannot separate the hues.
export const CATEGORY_STYLE: Record<Category, { color: string; shape: string; name: string }> = {
  infra: { color: "#5b8fc9", shape: "round-rectangle", name: "Infrastructure" },
  data: { color: "#c9a959", shape: "barrel", name: "Data store" },
  code: { color: "#3fae9e", shape: "hexagon", name: "Code & artifacts" },
  identity: { color: "#93a3b8", shape: "ellipse", name: "Identity" },
  finding: { color: "#e2685f", shape: "round-diamond", name: "Finding" },
};

// Shared with the search view's result chips.
export function labelColor(label: string): string {
  return CATEGORY_STYLE[category(label)].color;
}
