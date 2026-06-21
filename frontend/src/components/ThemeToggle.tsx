import { useTheme } from "../theme";

// A compact light/dark switch for the header. Shows the icon of the mode you'll
// switch *to*, with a matching tooltip/aria-label, and reads the current theme
// from the shared store so it stays in sync with OS changes.
export default function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  const label = `Switch to ${next} mode`;
  return (
    <button
      type="button"
      onClick={toggle}
      title={label}
      aria-label={label}
      className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-edge bg-panel text-slate-500 shadow-card transition hover:text-accent"
    >
      {theme === "dark" ? (
        // Sun (we're in dark → offer light)
        <svg viewBox="0 0 20 20" className="h-[18px] w-[18px]" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round">
          <circle cx="10" cy="10" r="3.4" />
          <path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4" />
        </svg>
      ) : (
        // Moon (we're in light → offer dark)
        <svg viewBox="0 0 20 20" className="h-[18px] w-[18px]" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
          <path d="M16.5 11.8A6.5 6.5 0 0 1 8.2 3.5a6.5 6.5 0 1 0 8.3 8.3Z" />
        </svg>
      )}
    </button>
  );
}
