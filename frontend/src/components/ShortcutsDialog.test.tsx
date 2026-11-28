import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ShortcutsDialog from "./ShortcutsDialog";
import { isTypingTarget, plainKey } from "../keyboard";

describe("ShortcutsDialog", () => {
  it("takes the focus, closes on Esc and on ?, and gives the focus back", () => {
    const before = document.createElement("button");
    document.body.append(before);
    before.focus();

    const close = vi.fn();
    const { unmount } = render(<ShortcutsDialog onClose={close} />);
    const dialog = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(dialog).toHaveFocus();

    fireEvent.keyDown(dialog, { key: "Escape" });
    fireEvent.keyDown(dialog, { key: "?" });
    expect(close).toHaveBeenCalledTimes(2);

    unmount();
    expect(before).toHaveFocus();
    before.remove();
  });

  it("lists the route list's keys", () => {
    render(<ShortcutsDialog onClose={() => {}} />);
    for (const key of ["j", "k", "t", "a", "Enter"]) {
      expect(screen.getByText(key, { selector: "kbd" })).toBeInTheDocument();
    }
  });
});

describe("plainKey", () => {
  const press = (target: EventTarget, init: KeyboardEventInit = {}) => {
    let seen: KeyboardEvent | null = null;
    const listen = (e: Event) => (seen = e as KeyboardEvent);
    window.addEventListener("keydown", listen);
    target.dispatchEvent(new KeyboardEvent("keydown", { key: "j", bubbles: true, ...init }));
    window.removeEventListener("keydown", listen);
    return seen!;
  };

  it("takes a bare key on the page and nothing typed into a field", () => {
    const field = document.createElement("textarea");
    const editable = document.createElement("div");
    editable.setAttribute("contenteditable", "true");
    const inDialog = document.createElement("button");
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    dialog.append(inDialog);
    document.body.append(field, editable, dialog);

    expect(plainKey(press(document.body))).toBe(true);
    expect(plainKey(press(document.body, { metaKey: true }))).toBe(false);
    expect(plainKey(press(document.body, { altKey: true }))).toBe(false);
    expect(plainKey(press(field))).toBe(false);
    expect(plainKey(press(editable))).toBe(false);
    expect(plainKey(press(inDialog))).toBe(false);
    expect(isTypingTarget(document.createElement("button"))).toBe(false);

    field.remove();
    editable.remove();
    dialog.remove();
  });
});
