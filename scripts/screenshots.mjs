// Regenerate the README screenshots from a running stack.
//
//   make up-full && make seed && make seed-discovery && make seed-validation
//   node scripts/screenshots.mjs
//
// Screenshots go stale silently: the dashboard was restructured while docs/*.png
// still showed a navigation and a headline metric that no longer exist, which is
// the worst kind of documentation rot because it looks fine until someone compares
// it to the product. This script makes refreshing them a command rather than a
// chore, so the images in the README track the UI they claim to show.
//
// It drives headless Chrome over the DevTools Protocol using Node's built-in
// WebSocket (Node 22+), so it adds no dependency to a repo that deliberately has
// almost none.

import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const APP = process.env.APP_URL ?? "http://localhost:3000";
const OUT = process.env.OUT_DIR ?? "docs";
const PORT = 9333;
const CHROME =
  process.env.CHROME ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

// Each shot: where to go, what to do once there, and what to call the file. The
// actions run in the page, so they can dismiss onboarding and open panels the same
// way a reader would before taking the picture.
// The app reads the view from the hash on mount only, so switching by URL after
// load is a same-document navigation that changes nothing. Each shot therefore
// clicks its way there, which is also what a reader does.
const nav = (label) => `
  [...document.querySelectorAll("aside button")]
    .find(b => b.textContent.includes(${JSON.stringify(label)}))?.click();
`;

const SHOTS = [
  { file: "screenshot-overview.png", act: "", settle: 2500 },
  { file: "screenshot-paths.png", act: nav("Attack paths"), settle: 3500 },
  { file: "screenshot-trust.png", act: nav("Trust"), settle: 2500 },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const profile = mkdtempSync(join(tmpdir(), "pg-shots-"));
  const chrome = spawn(
    CHROME,
    [
      "--headless=new",
      "--disable-gpu",
      "--hide-scrollbars",
      "--no-first-run",
      "--no-default-browser-check",
      `--user-data-dir=${profile}`,
      `--remote-debugging-port=${PORT}`,
      "--window-size=1600,1000",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  try {
    const ws = await connect();
    for (const shot of SHOTS) {
      await capture(ws, shot);
      console.log(`  wrote ${OUT}/${shot.file}`);
    }
    ws.close();
  } finally {
    chrome.kill();
    // Chrome flushes its profile asynchronously, so removing the directory the
    // instant after kill() races its last writes. Give it a moment, and never let
    // temp-dir cleanup fail a run whose screenshots already landed.
    await sleep(500);
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {
      /* the OS reaps its own temp dir */
    }
  }
}

// connect waits for Chrome's debugging endpoint, then attaches to its page target.
async function connect() {
  for (let i = 0; i < 40; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) {
        const ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((res, rej) => {
          ws.onopen = res;
          ws.onerror = rej;
        });
        return ws;
      }
    } catch {
      /* Chrome is still starting */
    }
    await sleep(250);
  }
  throw new Error("Chrome DevTools endpoint never came up");
}

let nextId = 1;
function send(ws, method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const onMessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== id) return;
      ws.removeEventListener("message", onMessage);
      msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result);
    };
    ws.addEventListener("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function capture(ws, shot) {
  // localStorage is per-origin, so the onboarding flag has to be written from a
  // page already loaded there; the reload after it starts the app already dismissed.
  await send(ws, "Page.navigate", { url: APP });
  await sleep(1200);
  await send(ws, "Runtime.evaluate", {
    expression: `localStorage.setItem("pg_intro_dismissed_v1", "1")`,
  });
  await send(ws, "Page.reload", {});
  await sleep(2500);

  if (shot.act) {
    await send(ws, "Runtime.evaluate", { expression: shot.act });
    await sleep(shot.settle);
  }

  const { data } = await send(ws, "Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, shot.file), Buffer.from(data, "base64"));
}

main().catch((err) => {
  console.error("screenshots:", err.message);
  process.exit(1);
});
