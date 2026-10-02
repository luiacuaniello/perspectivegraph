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
//   - images are copied under public/img/ and linked from there;
//   - the page's first sentence becomes its description (search results, link previews), and
//     its last commit its "last updated" date.
// The front page is the site's own (landing/index.mdx): it only points into these pages.
import { execFileSync } from "node:child_process";
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
  "README.md": "overview",
  "docs/EVALUATION.md": "evaluation",
  "docs/POSITIONING.md": "positioning",
  "docs/MANUAL.md": "manual",
  "docs/manual/concepts.md": "manual/concepts",
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
  "ROADMAP.md": "roadmap",
  "SUPPORT.md": "support",
  "ADOPTERS.md": "adopters",
  "GOVERNANCE.md": "governance",
};

// A page outside docs/ is rebuilt and link-checked only when the workflow's path filter
// names it, so one missing from the filter is published once and then never checked again.
// ROADMAP, SUPPORT, ADOPTERS and GOVERNANCE joined the site without joining the filter.
const WORKFLOW = readFileSync(join(REPO, ".github", "workflows", "docs.yml"), "utf8");
// Twice: once under push (publishing) and once under pull_request (the check).
const untriggered = Object.keys(PAGES).filter((f) => !f.startsWith("docs/") && WORKFLOW.split(`- "${f}"`).length - 1 < 2);
if (untriggered.length) {
  throw new Error(`.github/workflows/docs.yml does not run on changes to ${untriggered.join(", ")}: add them to both path filters`);
}

const IMAGE = /\.(png|svg|gif|jpe?g|webp)$/i;

// A sentence that wraps just before a "+" or a "-" - "subnets + route_tables", "the mean - the
// median" - starts its next line with what Markdown reads as a list marker, and the rest of the
// sentence renders as a bullet. GitHub and the site both do it, so neither preview shows it as a
// mistake. Five had shipped before this check: a list item straight after a line of prose, with no
// blank line and no colon to introduce it, is almost always one.
const LIST_ITEM = /^\s*([-+*]|\d+[.)])\s/;
const strays = [];
function strayListItem(file, prev, line) {
  if (!/^[-+*] \S/.test(line) || !prev.trim()) return;
  if (LIST_ITEM.test(prev) || /^(\s|\||#|>|<)/.test(prev) || prev.trimEnd().endsWith(":")) return;
  strays.push(`${file}: "${prev.trim().slice(-50)}" / "${line.slice(0, 50)}"`);
}

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
    // The README opens with GitHub's front matter: a centred logo and wordmark, the tagline, and
    // a row of badges. The site has its own logo, the tagline is on the front page, and badges
    // render one per line outside GitHub's centred paragraph.
    text = text
      .replace(/^<h1[\s\S]*?<\/h1>\s*/, "")
      .replace(/^<p align="center"><strong>[\s\S]*?<\/p>\s*/, "")
      .replace(/^<p align="center">\s*<a[\s\S]*?<\/p>\s*/, "");
    title = "Overview";
  } else {
    const m = text.match(/^# (.+)\n+/);
    if (!m) throw new Error(`${file}: no "# Title" on the first line`);
    title = m[1].trim();
    text = text.slice(m[0].length);
  }
  const out = [];
  let inFence = false;
  let prev = "";
  for (const line of text.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    if (inFence || line.startsWith("```")) {
      out.push(line);
      prev = "";
      continue;
    }
    strayListItem(file, prev, line);
    prev = line;
    out.push(
      line
        .replace(/\]\(([^)\s]+)\)/g, (_, t) => `](${rewriteTarget(t, file)})`)
        .replace(/\b(src|href|srcset)="([^"]+)"/g, (_, a, t) => `${a}="${rewriteTarget(t, file)}"`),
    );
  }
  const description = describe(text);
  const updated = lastCommit(file);
  const front = [
    "---",
    `title: ${JSON.stringify(title)}`,
    ...(description ? [`description: ${JSON.stringify(description)}`] : []),
    `editUrl: ${JSON.stringify(`${GITHUB}/edit/main/${file}`)}`,
    ...(updated ? [`lastUpdated: ${updated}`] : []),
    "---",
    "",
  ].join("\n");
  const dest = join(OUT, `${PAGES[file]}.md`);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, front + out.join("\n"));
}

// describe returns the page's opening sentence as plain text: the manual pages' line after
// "Part of the manual.", otherwise the first paragraph of prose. It is what a search result and a
// shared link show under the title; without it every page carried the site's one description.
function describe(text) {
  const plain = (s) =>
    s
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
      .replace(/[*_`]/g, "")
      .replace(/\s+/g, " ")
      .trim();
  for (const para of text.split(/\n\s*\n/)) {
    const p = para.trim();
    if (!p || /^(#|<|!|\||>|```|-|\d+\.|\{)/.test(p)) continue;
    let t = plain(p.replace(/^\*Part of the \[[^\]]+\]\([^)]+\)\.\*\s*/, ""));
    if (t.length < 40) continue;
    const end = t.search(/[.!?](\s|$)/);
    if (end > 60) t = t.slice(0, end + 1);
    return t.length > 240 ? `${t.slice(0, t.lastIndexOf(" ", 236))}…` : t;
  }
  return "";
}

// lastCommit is the date of the last commit that touched a source file, which is when its page
// last changed. On a shallow clone every file's last commit is the one checked out, so every page
// would claim to be new: there the date is left off rather than made up.
const history = (() => {
  try {
    return execFileSync("git", ["rev-parse", "--is-shallow-repository"], { cwd: REPO }).toString().trim() === "false";
  } catch {
    return false;
  }
})();
function lastCommit(file) {
  if (!history) return "";
  try {
    return execFileSync("git", ["log", "-1", "--format=%cs", "--", file], { cwd: REPO }).toString().trim();
  } catch {
    return "";
  }
}

rmSync(OUT, { recursive: true, force: true });
rmSync(IMG, { recursive: true, force: true });
for (const file of Object.keys(PAGES)) convert(file);
if (strays.length) {
  throw new Error(
    `a wrapped line starts with a list marker, so the rest of its sentence renders as a bullet - rewrap it, or put a blank line or a colon before a real list:\n  ${strays.join("\n  ")}`,
  );
}
copyFileSync(join(SITE, "landing", "index.mdx"), join(OUT, "index.mdx"));
mkdirSync(join(SITE, "src", "assets"), { recursive: true });
copyFileSync(join(REPO, "docs", "logo.svg"), join(SITE, "src", "assets", "logo.svg"));
// The front page shows the dashboard, and a shared link shows the same card the dashboard does.
mkdirSync(IMG, { recursive: true });
copyFileSync(join(REPO, "docs", "screenshot-overview.png"), join(IMG, "docs-screenshot-overview.png"));
copyFileSync(join(REPO, "docs", "social-card.png"), join(SITE, "public", "social-card.png"));
console.log(`synced ${Object.keys(PAGES).length} pages and the front page into src/content/docs`);
