// npm audit for one npm package of this repository - the dashboard, the documentation
// site - with named exceptions. Run it from the package's directory.
//
// The build fails on any high or critical advisory in the package's dependencies, as plain
// `npm audit --audit-level=high` did, except an advisory listed in the package's
// audit-exceptions.json. An exception names one advisory, says why it does not apply here,
// and carries a date by which it must be looked at again: past that date it stops excusing
// anything, so an exception cannot outlive the reasoning behind it. One that no longer
// matches an advisory is reported, so it gets removed rather than lingering.
//
// --strict-production audits the production dependencies first, and there no exception
// counts: what ships has none. The dashboard runs with it, so an exception can only ever
// excuse its build and test tooling. The documentation site does not: it ships nothing
// but the static pages it builds, and its dependencies are all build tooling.
//
// The registry sometimes answers with an error instead of a report. That is retried, and if
// it persists the build fails: a build never passes without having been audited.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const exceptions = JSON.parse(readFileSync(join(process.cwd(), "audit-exceptions.json"), "utf8"));
const strictProduction = process.argv.includes("--strict-production");
const today = new Date().toISOString().slice(0, 10);
const id = (url) => url.slice(url.lastIndexOf("/") + 1);

async function audit(extra) {
  for (const delay of [0, 10, 30]) {
    if (delay) {
      console.log(`the registry did not return a report; retrying in ${delay}s`);
      await sleep(delay * 1000);
    }
    let out;
    try {
      out = execFileSync("npm", ["audit", "--json", ...extra], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    } catch (e) {
      out = e.stdout; // npm exits non-zero when it finds anything
    }
    try {
      const parsed = JSON.parse(out);
      if (parsed && typeof parsed.vulnerabilities === "object") {
        return parsed;
      }
    } catch {
      // not a report: try again
    }
  }
  console.error("::error::npm audit could not get a report from the registry after 3 attempts - re-run the job.");
  process.exit(1);
}

// The advisories themselves: an entry whose `via` is an object is the advisory; one whose
// `via` is a package name only depends on a vulnerable package, and is the same finding.
function highAdvisories(report) {
  const advisories = new Map();
  for (const [pkg, v] of Object.entries(report.vulnerabilities)) {
    for (const via of v.via ?? []) {
      if (typeof via === "object" && ["high", "critical"].includes(via.severity)) {
        advisories.set(via.url, { ...via, pkg });
      }
    }
  }
  return advisories;
}

let failing = 0;
if (strictProduction) {
  for (const [url, a] of highAdvisories(await audit(["--omit=dev"]))) {
    failing++;
    console.error(`::error::${a.severity}: ${id(url)} in ${a.pkg}, a production dependency - ${a.title} (no exception applies to what ships)`);
  }
}

const advisories = highAdvisories(await audit([]));
for (const [url, a] of advisories) {
  const ex = exceptions.find((e) => e.id === id(url));
  if (ex && ex.reviewBy >= today) {
    console.log(`excepted until ${ex.reviewBy}: ${id(url)} (${a.pkg}) - ${ex.reason}`);
    continue;
  }
  failing++;
  const why = ex ? `its exception expired on ${ex.reviewBy}: look again` : "no exception";
  console.error(`::error::${a.severity}: ${id(url)} in ${a.pkg} - ${a.title} (${why})`);
}
for (const ex of exceptions) {
  if (![...advisories.keys()].some((url) => id(url) === ex.id)) {
    console.log(`::warning::exception ${ex.id} matches no advisory any more: remove it from audit-exceptions.json`);
  }
}
if (failing) {
  process.exit(1);
}
console.log(
  strictProduction
    ? "npm audit: no high or critical advisory in production, and none elsewhere without a current exception"
    : "npm audit: no high or critical advisory without a current exception",
);
