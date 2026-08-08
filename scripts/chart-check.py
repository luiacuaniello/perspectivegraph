#!/usr/bin/env python3
"""Assert every rendered workload is admissible and self-healing.

Two gates, both about what a cluster does with these manifests rather than about style.

FIRST: the `restricted` Pod Security Standard.

A cluster that enforces `restricted` is the normal case wherever this gets deployed, and
a pod that misses one field is not "less hardened" there - it is refused admission. So
this is a compatibility gate as much as a security one.

It deliberately checks the four fields `restricted` actually requires and NOT
readOnlyRootFilesystem, which the standard does not mandate and which the bundled NATS
and Postgres genuinely need (JetStream writes its store; Postgres writes its data dir).

Init containers are checked too. They are the easiest place to forget, and one
non-compliant init container refuses the entire pod.

SECOND: every container declares a readiness AND a liveness probe. They answer different
questions - "can it serve" versus "is it wedged" - and readiness alone means a hung
process leaves the Service and then sits there for ever. With the governance stores
single-writer the backend runs at replicas: 1, so nothing takes over: one wedged pod is
an outage that no longer heals itself.

Usage: helm template <chart> [-f values] | chart-check.py
"""
import sys
import yaml

WORKLOADS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")


def main() -> int:
    failures = []
    checked = 0
    for doc in yaml.safe_load_all(sys.stdin):
        if not doc or doc.get("kind") not in WORKLOADS:
            continue
        spec = doc["spec"]["template"]["spec"]
        pod = spec.get("securityContext") or {}
        name = doc["metadata"]["name"]

        missing_pod = []
        if pod.get("runAsNonRoot") is not True:
            missing_pod.append("pod.runAsNonRoot=true")
        if (pod.get("seccompProfile") or {}).get("type") not in ("RuntimeDefault", "Localhost"):
            missing_pod.append("pod.seccompProfile.type=RuntimeDefault")

        for kind in ("initContainers", "containers"):
            for c in spec.get(kind) or []:
                checked += 1
                ctr = c.get("securityContext") or {}
                missing = list(missing_pod)
                if ctr.get("allowPrivilegeEscalation") is not False:
                    missing.append("allowPrivilegeEscalation=false")
                if (ctr.get("capabilities") or {}).get("drop") != ["ALL"]:
                    missing.append('capabilities.drop=["ALL"]')
                label = f"{name}/{c['name']}" + (" (init)" if kind == "initContainers" else "")
                if missing:
                    failures.append(f"  {label}: {', '.join(missing)}")

                # Init containers run to completion, so probes are meaningless there.
                if kind == "containers":
                    for probe in ("readinessProbe", "livenessProbe"):
                        if not c.get(probe):
                            failures.append(f"  {label}: no {probe}")

    if not checked:
        print("chart-check: no workloads on stdin - did the render fail?", file=sys.stderr)
        return 1
    if failures:
        print(f"chart-check: {len(failures)} container(s) a cluster would refuse to admit, "
              f"or would never restart when wedged:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"chart-check: {checked} container(s) admissible and probed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
