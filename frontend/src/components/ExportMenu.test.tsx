import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import ExportMenu from "./ExportMenu";

describe("ExportMenu", () => {
  it("keeps the downloads behind one control, each saying who it is for", () => {
    render(<ExportMenu canExport showPlayground />);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Export" }));
    const items = screen.getAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual([
      "OSCAL assessment resultsFor GRC and auditors · JSON",
      "SIEM enrichmentPer-asset risk for Splunk, Elastic, Sentinel · NDJSON",
      "GraphQL playground ↗Query the API directly",
    ]);
    expect(items[0]).toHaveAttribute("download", "perspectivegraph-oscal.json");
    expect(items[1]).toHaveAttribute("download", "perspectivegraph-enrichment.ndjson");
  });

  it("closes on Escape", () => {
    render(<ExportMenu canExport showPlayground={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Export" }));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("offers the playground alone before there is anything to export", () => {
    render(<ExportMenu canExport={false} showPlayground />);
    fireEvent.click(screen.getByRole("button", { name: "Export" }));
    expect(screen.getAllByRole("menuitem")).toHaveLength(1);
  });

  it("renders nothing when it would be empty", () => {
    // The playground is hidden on an authenticated API (GraphiQL cannot carry a token).
    const { container } = render(<ExportMenu canExport={false} showPlayground={false} />);
    expect(container).toBeEmptyDOMElement();
  });
});
