import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import EngineVersion from "./EngineVersion";
import { fetchEngine } from "../api/client";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  fetchEngine: vi.fn(),
}));

const engine = vi.mocked(fetchEngine);

// The foot of the page is how someone looking at an instance tells which release computed
// it. Each case pins what it may claim: a link only for a published release, the build as
// it is otherwise, and nothing at all rather than a version it cannot vouch for.
describe("EngineVersion", () => {
  beforeEach(() => {
    engine.mockReset();
  });

  it("links a published release to its release notes", async () => {
    engine.mockResolvedValue({ version: "v1.40.0" });
    render(<EngineVersion live />);

    const link = await screen.findByRole("link", { name: "Release notes for v1.40.0" });
    expect(link).toHaveAttribute("href", "https://github.com/luiacuaniello/perspectivegraph/releases/tag/v1.40.0");
    expect(link).toHaveTextContent("v1.40.0");
    expect(screen.getByRole("contentinfo")).toHaveTextContent("PerspectiveGraph engine v1.40.0");
  });

  it("shows a local build as it is, without a link", async () => {
    engine.mockResolvedValue({ version: "3f2a91c" });
    render(<EngineVersion live />);

    expect(await screen.findByText("3f2a91c")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("says nothing when the engine cannot answer", async () => {
    engine.mockRejectedValue(new Error('Cannot query field "engine" on type "Query".'));
    const { container } = render(<EngineVersion live />);

    await vi.waitFor(() => expect(engine).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("does not ask while the backend is unreachable, and asks again when it is back", async () => {
    engine.mockResolvedValue({ version: "v1.40.1" });
    const { rerender } = render(<EngineVersion live={false} />);
    expect(engine).not.toHaveBeenCalled();

    rerender(<EngineVersion live />);
    expect(await screen.findByText("v1.40.1")).toBeInTheDocument();
    expect(engine).toHaveBeenCalledTimes(1);
  });
});
