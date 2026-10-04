// npm audit for the documentation site, with named exceptions.
//
// The build fails on any high or critical advisory in the site's dependencies, as plain
// `npm audit --audit-level=high` did, except an advisory listed in audit-exceptions.json.
// An exception names one advisory, says why it does not apply here, and carries a date by
// which it must be looked at again: past that date it stops excusing anything, so an
// exception cannot outlive the reasoning behind it. One that no longer matches an advisory
// is reported, so it gets removed rather than lingering.
//
// The registry sometimes answers with an error instead of a report. That is retried, and if
// it persists the build fails: a build never passes without having been audited.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const exceptions = JSON.parse(readFileSync(new URL("../audit-exceptions.json", import.meta.url), "utf8"));
const today = new Date().toISOString().slice(0, 10);

let report;
for (const delay of [0, 10, 30]) {
  if (delay) {
    console.log(`the registry did not return a report; retrying in ${delay}s`);
    await sleep(delay * 1000);
  }
  let out;
  try {
    out = execFileSync("npm", ["audit", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch (e) {
    out = e.stdout; // npm exits non-zero when it finds anything
  }
  try {
    const parsed = JSON.parse(out);
    if (parsed && typeof parsed.vulnerabilities === "object") {
      report = parsed;
      break;
    }
  } catch {
    // not a report: try again
  }
}
if (!report) {
  console.error("::error::npm audit could not get a report from the registry after 3 attempts - re-run the job.");
  process.exit(1);
}

// The advisories themselves: an entry whose `via` is an object is the advisory; one whose
// `via` is a package name only depends on a vulnerable package, and is the same finding.
const advisories = new Map();
for (const [pkg, v] of Object.entries(report.vulnerabilities)) {
  for (const via of v.via ?? []) {
    if (typeof via === "object" && ["high", "critical"].includes(via.severity)) {
      advisories.set(via.url, { ...via, pkg });
    }
  }
}

const id = (url) => url.slice(url.lastIndexOf("/") + 1);
let failing = 0;
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
console.log("npm audit: no high or critical advisory without a current exception");
