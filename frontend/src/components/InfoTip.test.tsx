import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import InfoTip from "./InfoTip";

// On an iPhone there is no hover and Safari does not focus a tapped button, so the tooltip
// has to open on the tap itself - it did not, and every explanation was out of reach.
describe("InfoTip", () => {
  it("opens on a tap and closes on a second one", () => {
    render(<InfoTip text="KEV is CISA's catalogue of exploited CVEs." />);
    const button = screen.getByRole("button", { name: /KEV is CISA/ });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("tooltip")).toBeNull();

    fireEvent.click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tooltip")).toHaveTextContent("KEV is CISA's catalogue of exploited CVEs.");

    fireEvent.click(button);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("closes on a tap elsewhere and on Escape", () => {
    render(
      <div>
        <InfoTip text="EPSS is a 30-day exploitation forecast." />
        <p>elsewhere</p>
      </div>,
    );
    const button = screen.getByRole("button", { name: /EPSS/ });

    fireEvent.click(button);
    fireEvent.pointerDown(screen.getByText("elsewhere"));
    expect(screen.queryByRole("tooltip")).toBeNull();

    fireEvent.click(button);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  // Hover and keyboard focus still show it, as before.
  it("shows on hover and on keyboard focus", () => {
    render(<InfoTip text="Monte Carlo samples the graph many times." />);
    const button = screen.getByRole("button", { name: /Monte Carlo/ });

    fireEvent.pointerEnter(button.parentElement!);
    expect(screen.getByRole("tooltip")).toBeInTheDocument();
    fireEvent.pointerLeave(button.parentElement!);
    expect(screen.queryByRole("tooltip")).toBeNull();

    fireEvent.focus(button);
    expect(screen.getByRole("tooltip")).toBeInTheDocument();
    fireEvent.blur(button);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  // A transparent bubble still counts as overflow, and gave scrolling panels a sideways
  // scroll on a phone: closed, it must not be in the layout at all.
  it("is not in the document while closed", () => {
    render(<InfoTip text="Closed tips take no room." />);
    expect(screen.queryByText("Closed tips take no room.")).toBeNull();
  });

  // Tips sit inside clickable rows and <summary> elements: the tap is for the tip only.
  it("does not pass the tap to what it sits in", () => {
    const onRow = vi.fn();
    render(
      <div onClick={onRow}>
        <InfoTip text="A choke point is an edge many routes share." />
      </div>,
    );
    fireEvent.click(screen.getByRole("button", { name: /choke point/ }));
    expect(onRow).not.toHaveBeenCalled();
  });
});
