// Theme state: a single source of truth for light/dark, persisted to
// localStorage and applied as a `.dark` class on <html> (which flips the CSS
// custom properties in index.css). First load honours a stored choice, then the
// OS preference. An inline script in index.html applies it before first paint so
// there's no flash of the wrong theme; this module keeps it in sync at runtime.
import { useSyncExternalStore } from "react";

export type Theme = "light" | "dark";

const STORAGE_KEY = "pg-theme";
const EVENT = "pg-themechange";

const prefersDark = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

/** The theme to use on first load: explicit choice wins, else OS preference. */
export function resolveInitialTheme(): Theme {
  return stored() ?? (prefersDark() ? "dark" : "light");
}

function apply(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme; // native form controls + scrollbars
}

/** Apply the resolved theme. Safe to call repeatedly; mirrors the inline script. */
export function initTheme() {
  apply(resolveInitialTheme());
}

/** Persist and apply a theme, notifying subscribers (the toggle, the graph). */
export function setTheme(theme: Theme) {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* private mode / disabled storage — still apply for this session */
  }
  apply(theme);
  window.dispatchEvent(new CustomEvent<Theme>(EVENT, { detail: theme }));
}

function currentTheme(): Theme {
  return typeof document !== "undefined" && document.documentElement.classList.contains("dark")
    ? "dark"
    : "light";
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(EVENT, onChange);
  const mql = window.matchMedia("(prefers-color-scheme: dark)");
  // Follow the OS only while the user hasn't made an explicit choice.
  const onOS = () => {
    if (!stored()) {
      apply(prefersDark() ? "dark" : "light");
      onChange();
    }
  };
  mql.addEventListener("change", onOS);
  return () => {
    window.removeEventListener(EVENT, onChange);
    mql.removeEventListener("change", onOS);
  };
}

/** React hook: current theme + a toggle. Re-renders on any theme change. */
export function useTheme(): { theme: Theme; toggle: () => void } {
  const theme = useSyncExternalStore(subscribe, currentTheme, (): Theme => "light");
  const toggle = () => setTheme(theme === "dark" ? "light" : "dark");
  return { theme, toggle };
}
