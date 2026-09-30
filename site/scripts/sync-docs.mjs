// Copy the repository's documentation into the Starlight content folder.
//
// The Markdown in docs/ (and the README) stays the one source: it is what GitHub renders
// and what a pull request changes, and this site is built from it on every merge. Nothing
// under src/content/docs/ is edited by hand - it is regenerated here, and ignored by git.
//
// What the copy changes, and only that:
//   - the first "# Title" becomes the page's front matter (Starlight prints the title);
//   - links between documents become links between pages ("../MANUAL.md#x" -> "/manual/#x");
//   - links into the code (../backend/...) point at the file on GitHub;
//   - images are copied under public/img/ and linked from there.
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const SITE = fileURLToPath(new URL("..", import.meta.url));
const REPO = join(SITE, "..");
const OUT = join(SITE, "src", "content", "docs");
const IMG = join(SITE, "public", "img");
const GITHUB = "https://github.com/luiacuaniello/perspectivegraph";

// Repository file -> page slug. The sidebar order lives in astro.config.mjs.
export const PAGES = {
  "README.md": "index",
  "docs/EVALUATION.md": "evaluation",
  "docs/POSITIONING.md": "positioning",
  "docs/MANUAL.md": "manual",
  "docs/manual/quick-start.md": "manual/quick-start",
  "docs/manual/how-it-works.md": "manual/how-it-works",
  "docs/manual/scoring.md": "manual/scoring",
  "docs/manual/accuracy.md": "manual/accuracy",
  "docs/manual/ci-gate.md": "manual/ci-gate",
  "docs/manual/integrations.md": "manual/integrations",
  "docs/manual/working-the-findings.md": "manual/working-the-findings",
  "docs/manual/ai-and-mcp.md": "manual/ai-and-mcp",
  "docs/manual/onboarding.md": "manual/onboarding",
  "docs/manual/security.md": "manual/security",
  "docs/manual/kubernetes.md": "manual/kubernetes",
  "docs/manual/running.md": "manual/running",
  "docs/OPERATIONS.md": "operations",
  "docs/SCALE.md": "scale",
  "docs/UPGRADING.md": "upgrading",
  "docs/API-STABILITY.md": "api-stability",
  "docs/THREAT-MODEL.md": "threat-model",
  "SECURITY.md": "security-policy",
  "CONTRIBUTING.md": "contributing",
};

const IMAGE = /\.(png|svg|gif|jpe?g|webp)$/i;

function route(slug, frag) {
  const path = slug === "index" ? "/" : `/${slug}/`;
  return frag ? `${path}#${frag}` : path;
}

function rewriteTarget(target, fromFile) {
  if (/^(https?:|mailto:|#)/.test(target)) return target;
  const [path, frag] = target.split("#");
  const repoPath = normalize(join(dirname(fromFile), path)).split("\\").join("/");
  if (PAGES[repoPath]) return route(PAGES[repoPath], frag);
  const abs = join(REPO, repoPath);
  if (!existsSync(abs)) return target; // left for the link validator to report
  if (IMAGE.test(repoPath)) {
    const name = repoPath.replaceAll("/", "-");
    mkdirSync(IMG, { recursive: true });
    copyFileSync(abs, join(IMG, name));
    return `/img/${name}`;
  }
  const kind = statSync(abs).isDirectory() ? "tree" : "blob";
  return `${GITHUB}/${kind}/main/${repoPath}${frag ? `#${frag}` : ""}`;
}

function convert(file) {
  let text = readFileSync(join(REPO, file), "utf8");
  let title;
  if (file === "README.md") {
    // The README opens with a centred logo and wordmark for GitHub; the site has its own.
    text = text.replace(/^<h1[\s\S]*?<\/h1>\s*/, "");
    title = "PerspectiveGraph";
  } else {
    const m = text.match(/^# (.+)\n+/);
    if (!m) throw new Error(`${file}: no "# Title" on the first line`);
    title = m[1].trim();
    text = text.slice(m[0].length);
  }
  const out = [];
  let inFence = false;
  for (const line of text.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    if (inFence || line.startsWith("```")) {
      out.push(line);
      continue;
    }
    out.push(
      line
        .replace(/\]\(([^)\s]+)\)/g, (_, t) => `](${rewriteTarget(t, file)})`)
        .replace(/\b(src|href|srcset)="([^"]+)"/g, (_, a, t) => `${a}="${rewriteTarget(t, file)}"`),
    );
  }
  const front = [
    "---",
    `title: ${JSON.stringify(title)}`,
    `editUrl: ${JSON.stringify(`${GITHUB}/edit/main/${file}`)}`,
    // The home page's title is the site's name, and the browser tab read
    // "PerspectiveGraph | PerspectiveGraph".
    ...(file === "README.md"
      ? ["tableOfContents: false", "head:", "  - tag: title", "    content: PerspectiveGraph documentation"]
      : []),
    "---",
    "",
  ].join("\n");
  const dest = join(OUT, `${PAGES[file]}.md`);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, front + out.join("\n"));
}

rmSync(OUT, { recursive: true, force: true });
rmSync(IMG, { recursive: true, force: true });
for (const file of Object.keys(PAGES)) convert(file);
mkdirSync(join(SITE, "src", "assets"), { recursive: true });
copyFileSync(join(REPO, "docs", "logo.svg"), join(SITE, "src", "assets", "logo.svg"));
console.log(`synced ${Object.keys(PAGES).length} pages into src/content/docs`);
