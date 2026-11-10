#!/usr/bin/env python3
"""Carry an image pin from the file Dependabot updates to the files it does not read.

Dependabot moves NATS in the chart's values.yaml and Keycloak in docker-compose.yml. The
same pins, tag and digest, also sit where no Dependabot ecosystem looks: NATS in the
compose stack, in the image list Artifact Hub scans and in the CI job that runs a real
broker; Keycloak in the Kubernetes manifest of the SSO demo. A Go test holds each set equal
(internal/config), so a Dependabot pull request for either fails until the rest follow -
three times for NATS in two months. This makes that one command, run on the pull
request's branch:

    make sync-pins                          # or: python3 scripts/sync-pins.py
    python3 scripts/sync-pins.py --check    # change nothing; exit 1 when a pin differs

Exit 2 when a file holds its pin other than exactly once: that is a file to fix by hand,
not one to rewrite.
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# name, the pin, the file Dependabot updates, the files that follow it.
PINS = [
    (
        "NATS",
        re.compile(r"nats:[0-9][^\s@\"']*@sha256:[0-9a-f]{64}"),
        "deploy/helm/perspectivegraph/values.yaml",
        ["docker-compose.yml", "deploy/helm/perspectivegraph/Chart.yaml", ".github/workflows/ci.yml"],
    ),
    (
        "Keycloak",
        re.compile(r"quay\.io/keycloak/keycloak:[0-9][^\s@\"']*@sha256:[0-9a-f]{64}"),
        "docker-compose.yml",
        ["deploy/keycloak/k8s-keycloak-demo.yaml"],
    ),
]


def only_pin(name, pattern, rel):
    found = pattern.findall((ROOT / rel).read_text(encoding="utf-8"))
    if len(found) != 1:
        print(f"{rel} pins {name} {len(found)} times, want exactly once: {found}", file=sys.stderr)
        sys.exit(2)
    return found[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="change nothing; exit 1 when a pin differs")
    args = ap.parse_args()

    behind = False
    for name, pattern, source, followers in PINS:
        want = only_pin(name, pattern, source)
        for rel in followers:
            have = only_pin(name, pattern, rel)
            if have == want:
                continue
            behind = True
            if args.check:
                print(f"{name}: {rel} pins {have}, {source} pins {want}")
                continue
            path = ROOT / rel
            path.write_text(path.read_text(encoding="utf-8").replace(have, want), encoding="utf-8")
            print(f"{name}: {rel} now pins {want}")
    if not behind:
        print("every pin matches the file Dependabot updates")
    sys.exit(1 if args.check and behind else 0)


if __name__ == "__main__":
    main()
