// Regenerate the README's demo GIF from a running stack.
//
//   make up-full && make seed && make seed-discovery && make seed-validation
//   node scripts/demo-gif.mjs
//
// The GIF is the first thing a visitor sees, and it goes stale the same silent way the
// screenshots do - it kept showing the previous palette and a navigation that no longer
// exists long after the UI had moved on. This makes refreshing it a command.
//
// It drives headless Chrome over the DevTools Protocol with Node's built-in WebSocket,
// exactly as scripts/screenshots.mjs does, then hands the frames to Pillow to assemble.
// Python does the encoding because Node has no GIF encoder in the standard library and
// this repo does not add a dependency for one.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const APP = process.env.APP_URL ?? "http://localhost:3000";
const OUT = process.env.OUT_DIR ?? "docs";
const PORT = 9334; // not 9333: so this can run while screenshots.mjs is open
const CHROME =
  process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
// Pillow lives in the Homebrew python on this project's machines; the system python3
// has no PIL. Override if yours differs.
const PYTHON = process.env.PYTHON ?? "/usr/local/bin/python3";

// The story the caption promises: what is exploitable now → the ranked routes → one
// route's kill chain and its generated fix → whether the scores can be trusted.
//
// `hold` frames are what give a reader time to actually read a screen; without them the
// GIF flicks through four views faster than anyone can follow, which is the failure mode
// of most product GIFs.
const nav = (label) => `
  [...document.querySelectorAll("aside button")]
    .find(b => b.textContent.includes(${JSON.stringify(label)}))?.click();
`;

const SCENES = [
  { act: "", hold: 22, label: "Today" },
  { act: nav("Attack paths"), hold: 16, label: "the ranked routes" },
  {
    // Open the top route's detail and scroll its kill chain into view.
    act: `
      (() => {
        const rows = document.querySelectorAll(".group\\\\/row button");
        rows[0]?.click();
      })();
    `,
    hold: 20,
    label: "the kill chain",
  },
  {
    // The generated fix sits below the kill chain - inside the detail column, which is
    // its OWN scroll container. Scrolling `window` here moved nothing and the scene
    // silently showed more kill chain instead of the fix the caption promises.
    act: `
      (() => {
        // Scroll to the fix BY NAME rather than by guessing a container. Picking "the
        // first scrollable div" found the route list on the left and quietly scrolled
        // that instead, so the scene showed more rows where the caption promises a
        // Terraform fix. scrollIntoView finds the right ancestor on its own.
        const h = [...document.querySelectorAll("*")].find(
          e => e.children.length === 0 && /Suggested remediation/i.test(e.textContent || "")
        );
        h?.scrollIntoView({ behavior: "smooth", block: "center" });
      })();
    `,
    hold: 18,
    label: "the generated fix",
  },
  { act: nav("Trust"), hold: 24, label: "whether to trust it" },
];

const FRAME_MS = 120; // matches the previous GIF's cadence
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const profile = mkdtempSync(join(tmpdir(), "pg-gif-"));
  const frames = mkdtempSync(join(tmpdir(), "pg-frames-"));
  mkdirSync(frames, { recursive: true });
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
      // 1800x1012 at deviceScaleFactor 1 downsamples to a crisp 900x506, which is the
      // size the README has always used.
      "--window-size=1800,1012",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  let n = 0;
  try {
    const ws = await connect();
    await send(ws, "Page.navigate", { url: APP });
    await sleep(1500);
    // Dismiss onboarding from a page already on the origin, then reload into the app.
    await send(ws, "Runtime.evaluate", {
      expression: `localStorage.setItem("pg_intro_dismissed_v1", "1"); localStorage.setItem("pg-theme", "dark");`,
    });
    await send(ws, "Page.reload", {});
    await sleep(3000);

    for (const scene of SCENES) {
      if (scene.act) {
        await send(ws, "Runtime.evaluate", { expression: scene.act });
        await sleep(600); // let the view settle before the first frame of the scene
      }
      for (let i = 0; i < scene.hold; i++) {
        const { data } = await send(ws, "Page.captureScreenshot", { format: "png" });
        writeFileSync(join(frames, `f${String(n++).padStart(4, "0")}.png`), Buffer.from(data, "base64"));
        await sleep(FRAME_MS);
      }
      console.log(`  captured ${scene.hold} frames · ${scene.label}`);
    }
    ws.close();
  } finally {
    chrome.kill();
    await sleep(500);
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {
      /* the OS reaps its own temp dir */
    }
  }

  console.log(`  assembling ${n} frames…`);
  const res = spawnSync(PYTHON, [join("scripts", "assemble-gif.py"), frames, join(OUT, "demo.gif"), String(FRAME_MS)], {
    stdio: "inherit",
  });
  rmSync(frames, { recursive: true, force: true });
  if (res.status !== 0) {
    throw new Error("assembling the GIF failed - is Pillow installed for " + PYTHON + "?");
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

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
