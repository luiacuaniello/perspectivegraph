import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// slate-400 cannot carry small text in either theme at WCAG 2.2 AA (1.4.3, 4.5:1): it
// measured 2.6:1 on the light panel and 3.8:1 on the dark one, found by running axe-core
// against the public demo. It stays for borders and fills; text starts at slate-500.
// This holds the line for components that do not exist yet, which no audit of today's
// pages can.
const sources = import.meta.glob<string>("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true });
// Read from disk: vitest.config.ts sets css: false, so an imported stylesheet arrives
// empty; and under jsdom import.meta.url is not a file URL. Vitest runs from the frontend
// root, here and in CI.
const stylesheet = readFileSync(join(process.cwd(), "src", "index.css"), "utf8");

describe("text contrast", () => {
  it("never sets text in slate-400", () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => !path.endsWith("contrast.test.ts"))
      .flatMap(([path, src]) =>
        src.split("\n").flatMap((line, i) => (/\btext-slate-400\b/.test(line) ? [`${path}:${i + 1}`] : [])),
      );
    expect(offenders, "use text-slate-500 or darker; slate-400 fails 4.5:1 as text").toEqual([]);
  });

  // Coloured text is set in the -600/-700/-800 shades, which read well on light surfaces
  // and not at all on dark ones: a falco badge in text-indigo-700 measured 1.84:1 in the
  // dark theme, because index.css lightened amber, red, emerald and teal but nobody had
  // added indigo. Every shade used for text needs its dark-theme override.
  it("gives every dark text shade a dark-theme override", () => {
    const css = stylesheet;
    const used = new Set(
      Object.entries(sources)
        .filter(([path]) => !path.endsWith("contrast.test.ts"))
        .flatMap(([, src]) => [...src.matchAll(/\btext-([a-z]+-(?:600|700|800))\b/g)].map((m) => m[1]))
        .filter((shade) => !shade.startsWith("slate-")),
    );
    const missing = [...used].filter((shade) => !css.includes(`.dark [class*="text-${shade}"]`)).sort();
    expect(missing, "add a .dark [class*=\"text-<shade>\"] rule in index.css").toEqual([]);
  });

  // Three failures an audit of the public demo could not see, because they need a writable
  // instance or a calibration state the demo's data does not reach. axe against a local
  // instance measured them for 1.25: white on the accent fill (2.15:1 in the dark theme,
  // whose accent is light), -600 text on white (emerald 3.65:1, amber 3.19:1), and
  // amber-700 on the amber tint (4.48:1).
  it("keeps the colour pairs that failed out of the sources", () => {
    const rules: [RegExp, string][] = [
      [/\bbg-accent\b(?![/\w-])[^"`]*\btext-white\b/, "text on the accent fill is text-panel: white fails on the dark theme's accent"],
      [/\btext-(?:emerald|amber)-600\b/, "use the -700 shade: -600 fails 4.5:1 on white"],
      [/\bbg-amber-500\/15\b[^"`]*\btext-amber-700\b/, "text on the amber tint is amber-800: amber-700 measured 4.48:1"],
    ];
    const offenders = Object.entries(sources)
      .filter(([path]) => !path.endsWith("contrast.test.ts"))
      .flatMap(([path, src]) =>
        src.split("\n").flatMap((line, i) =>
          rules.filter(([re]) => re.test(line)).map(([, why]) => `${path}:${i + 1} - ${why}`),
        ),
      );
    expect(offenders).toEqual([]);
  });

  it("actually reads the sources it guards", () => {
    // An empty glob would make the check above pass vacuously.
    expect(Object.keys(sources).length).toBeGreaterThan(20);
    expect(stylesheet).toContain('.dark [class*="text-');
  });
});
