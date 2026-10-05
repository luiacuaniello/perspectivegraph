#!/usr/bin/env python3
"""lab-record.py - turn a lab's checks into the record the dashboard shows.

A lab appends one JSON object per check to a rows file while it runs:

    {"case": ..., "question": ..., "referee": ..., "aws": ..., "engine": ..., "verdict": ..., "note": ...}

and calls this at the end to write backend/internal/labrecord/records/<lab>.json, which the
binary embeds (internal/labrecord). The engine version is read from git, so a record says
which code it checked. A record is published with every build, so any twelve-digit number -
an AWS account ID - is replaced before it is written, and the run is refused if a verdict
is not one of agree, disagree, unsettled.

    lab-record.py --lab public-access-lab-aws --title "..." --command "make ..." \
        --region eu-north-1 --cost free --rows rows.jsonl
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACCOUNT_ID = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
VERDICTS = {"agree", "disagree", "unsettled"}
FIELDS = ("case", "question", "referee", "aws", "engine", "verdict", "note")


def engine_version():
    try:
        return subprocess.run(["git", "-C", ROOT, "describe", "--tags", "--always", "--dirty"],
                              check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def scrub(value):
    if isinstance(value, str):
        return ACCOUNT_ID.sub("<account>", value)
    return value


def main():
    ap = argparse.ArgumentParser()
    for name in ("lab", "title", "command", "region", "cost", "rows"):
        ap.add_argument("--" + name, required=True)
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    checks = []
    with open(a.rows) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            unknown = set(row) - set(FIELDS)
            if unknown:
                sys.exit(f"lab-record: row {n} has unknown fields {sorted(unknown)}")
            if row.get("verdict") not in VERDICTS:
                sys.exit(f"lab-record: row {n} has verdict {row.get('verdict')!r}")
            checks.append({k: scrub(row[k]) for k in FIELDS if row.get(k) not in (None, "")})
    if not checks:
        sys.exit("lab-record: no checks - a run that checked nothing is not a record")

    record = {
        "lab": a.lab,
        "title": a.title,
        "command": a.command,
        "region": a.region,
        "engine": scrub(engine_version()),
        "ran_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cost": a.cost,
        "checks": checks,
    }
    out = a.out or os.path.join(ROOT, "backend", "internal", "labrecord", "records", a.lab + ".json")
    with open(out, "w") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
        f.write("\n")
    agreed = sum(c["verdict"] == "agree" for c in checks)
    print(f"  record: {agreed} of {len(checks)} checks agree -> {os.path.relpath(out, ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
