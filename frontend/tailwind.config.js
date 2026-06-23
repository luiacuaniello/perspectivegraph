/** @type {import('tailwindcss').Config} */

// Every themeable color is a CSS custom property holding space-separated RGB
// channels, wrapped so Tailwind's `/<alpha>` opacity modifiers keep working
// (e.g. `bg-accent/15` → `rgb(var(--c-accent) / 0.15)`). The light values live
// in `:root` and the dark overrides under `.dark` (see src/index.css), so the
// whole UI re-themes from one place instead of scattered `dark:` variants.
const c = (v) => `rgb(var(${v}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Surfaces & accent (semantic tokens)
        ink: c("--c-ink"), // app canvas + inset surfaces
        panel: c("--c-panel"), // cards / panels
        "panel-2": c("--c-panel-2"), // raised / inset surface
        edge: c("--c-edge"), // hairline borders
        accent: c("--c-accent"), // confident blue
        "accent-strong": c("--c-accent-strong"), // hover/active for accent
        "accent-soft": c("--c-accent-soft"), // accent-tinted surface
        muted: c("--c-muted"), // secondary text
        // The slate ramp is remapped to themed vars so the existing text
        // hierarchy (text-slate-400…900) inverts cleanly in dark mode.
        slate: {
          50: c("--c-slate-50"),
          100: c("--c-slate-100"),
          200: c("--c-slate-200"),
          300: c("--c-slate-300"),
          400: c("--c-slate-400"),
          500: c("--c-slate-500"),
          600: c("--c-slate-600"),
          700: c("--c-slate-700"),
          800: c("--c-slate-800"),
          900: c("--c-slate-900"),
        },
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(var(--c-shadow) / 0.05), 0 1px 3px 0 rgb(var(--c-shadow) / 0.08)",
        // A slightly lifted shadow for hover/selected panels and popovers.
        lift: "0 2px 4px -1px rgb(var(--c-shadow) / 0.1), 0 6px 16px -4px rgb(var(--c-shadow) / 0.16)",
        // Neon accent glow for the primary CTA, active nav, and lit cards.
        glow: "0 0 0 1px rgb(var(--c-accent) / 0.25), 0 4px 22px -3px rgb(var(--c-accent) / 0.5)",
        "glow-lg": "0 0 0 1px rgb(var(--c-accent) / 0.4), 0 10px 40px -6px rgb(var(--c-accent) / 0.65)",
      },
    },
  },
  plugins: [],
};
