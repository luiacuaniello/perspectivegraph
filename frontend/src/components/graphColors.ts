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

// Cool, saturated-enough corporate tones that read on a light canvas.
export const CATEGORY_STYLE: Record<Category, { color: string; shape: string; name: string }> = {
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
