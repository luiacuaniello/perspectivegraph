import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { BottomBar, TopBar } from "./Navigation";

// Two bars carry the same sections: tabs across the top on a desktop, a tab bar at the
// bottom on a phone. CSS decides which one shows, so both are always in the DOM here -
// which is exactly why each is checked on its own.

describe("TopBar", () => {
  it("marks the current section and counts the open routes", () => {
    render(<TopBar view="paths" onNavigate={() => {}} pathCount={14} live analyzedAt={null} />);
    const nav = screen.getByRole("navigation", { name: "Sections" });
    const current = within(nav).getByRole("button", { current: "page" });
    expect(current).toHaveTextContent("Attack paths");
    expect(current).toHaveTextContent("14");
    // Below lg the tab shows a short label; its name stays the full one, with the count.
    expect(current).toHaveAccessibleName("Attack paths, 14");
    expect(within(nav).getByRole("button", { name: "Today" })).not.toHaveAttribute("aria-current");
  });

  it("navigates when a tab is chosen", () => {
    const onNavigate = vi.fn();
    render(<TopBar view="today" onNavigate={onNavigate} pathCount={0} live />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Sections" })).getByRole("button", { name: "Trust" }));
    expect(onNavigate).toHaveBeenCalledWith("trust");
  });

  it("offers the assistant only when the backend has AI configured", () => {
    const { rerender } = render(<TopBar view="today" onNavigate={() => {}} pathCount={0} live />);
    expect(screen.queryByRole("button", { name: "AI assistant" })).not.toBeInTheDocument();
    rerender(<TopBar view="today" onNavigate={() => {}} pathCount={0} live aiEnabled />);
    expect(screen.getByRole("button", { name: "AI assistant" })).toBeInTheDocument();
  });

  it("says when the backend cannot be reached", () => {
    render(<TopBar view="today" onNavigate={() => {}} pathCount={0} live={false} />);
    expect(screen.getByRole("status")).toHaveAttribute("title", "backend unreachable");
  });

  it("offers search only when the engine has it", () => {
    const { rerender } = render(<TopBar view="today" onNavigate={() => {}} pathCount={0} live />);
    expect(screen.queryByRole("button", { name: "Search assets" })).not.toBeInTheDocument();
    rerender(<TopBar view="today" onNavigate={() => {}} pathCount={0} live onOpenSearch={() => {}} />);
    expect(screen.getByRole("button", { name: "Search assets" })).toBeInTheDocument();
  });
});

describe("BottomBar", () => {
  it("carries the same sections, with the current one marked", () => {
    const onNavigate = vi.fn();
    render(<BottomBar view="today" onNavigate={onNavigate} pathCount={14} aiEnabled />);
    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(within(nav).getByRole("button", { current: "page" })).toHaveTextContent("Today");
    expect(within(nav).getAllByRole("button").map((b) => b.textContent)).toEqual(["Today", "Paths14", "Trust", "Assistant"]);
    fireEvent.click(within(nav).getByRole("button", { name: /Paths/ }));
    expect(onNavigate).toHaveBeenCalledWith("paths");
  });
});
