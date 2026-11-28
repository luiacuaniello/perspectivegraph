// Single-key shortcuts must never fire while someone is typing: "j" in a question to the
// assistant, "t" in an owner's name. Nor with a modifier held, which belongs to the
// browser and the system (⌘K is the search palette's, handled where the palette opens).

export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  if (target instanceof HTMLElement && target.isContentEditable) return true;
  return target.closest("input, textarea, select, [contenteditable='true'], [contenteditable='']") !== null;
}

// plainKey reports whether a keydown is a bare key press a page shortcut may take: no
// modifier but Shift, not part of an IME composition, not in a field, and not inside a
// dialog, which handles its own keys.
export function plainKey(e: KeyboardEvent): boolean {
  if (e.defaultPrevented || e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return false;
  if (isTypingTarget(e.target)) return false;
  return !(e.target instanceof Element && e.target.closest("[role='dialog']"));
}
