#!/usr/bin/env python3
"""Assert the Content-Security-Policy stays true to what the page actually needs.

Two things rot silently and only show up as a blank dashboard in production:

  1. The CSP pins a sha256 of the inline <script> in index.html - the theme applied
     before first paint. Edit that script by a byte and the browser refuses to run it:
     the page loads unstyled, or flashes light before going dark, and nothing in the
     build says why. So the hash is recomputed here from index.html and compared.

  2. Two nginx configs serve the same SPA - the one baked into the image and the one the
     Helm chart mounts over it. The chart's used to carry no security headers at all
     while the image's did. Divergence means the header set you tested in `docker
     compose` is not the one Kubernetes serves.

Run: python3 scripts/csp-check.py   (from the repo root)
"""

import base64
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / "frontend" / "index.html"
CONFIGS = [
    ROOT / "frontend" / "nginx.conf",
    ROOT / "deploy" / "perspectivegraph" / "templates" / "frontend.yaml",
    ROOT / "deploy" / "helm" / "perspectivegraph" / "templates" / "frontend.yaml",
]

# Directives that must be present wherever a CSP is declared. These are the ones doing
# the work: without them the policy reads strict but permits the attack.
REQUIRED = {
    "default-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'none'",
    "frame-ancestors": "'none'",
}


def inline_script_hashes(html: str) -> set[str]:
    """sha256-<base64> for every inline <script> (those without a src attribute)."""
    out = set()
    for body in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S):
        digest = hashlib.sha256(body.encode()).digest()
        out.add("sha256-" + base64.b64encode(digest).decode())
    return out


def policies(text: str) -> list[str]:
    return re.findall(r'add_header\s+Content-Security-Policy\s+"([^"]+)"', text)


def main() -> int:
    if not INDEX.exists():
        print(f"csp-check: {INDEX} not found", file=sys.stderr)
        return 1
    wanted = inline_script_hashes(INDEX.read_text(encoding="utf-8"))
    problems: list[str] = []
    seen_any = False

    for cfg in CONFIGS:
        if not cfg.exists():
            continue
        found = policies(cfg.read_text(encoding="utf-8"))
        if not found:
            problems.append(f"{cfg.relative_to(ROOT)}: serves the SPA but declares no Content-Security-Policy")
            continue
        seen_any = True
        for policy in found:
            for directive, value in REQUIRED.items():
                if f"{directive} {value}" not in policy:
                    problems.append(
                        f"{cfg.relative_to(ROOT)}: policy is missing `{directive} {value}`"
                    )
            for h in wanted:
                if f"'{h}'" not in policy:
                    problems.append(
                        f"{cfg.relative_to(ROOT)}: index.html has an inline script whose hash "
                        f"{h} is not allowed by the policy - the browser will refuse to run it"
                    )
            # A hash pinned here that no longer matches any script is dead weight, and
            # hides the fact that the real script is unprotected.
            for stale in re.findall(r"'(sha256-[A-Za-z0-9+/=]+)'", policy):
                if stale not in wanted:
                    problems.append(
                        f"{cfg.relative_to(ROOT)}: policy allows {stale}, which matches no "
                        f"inline script in index.html - stale entry, remove it"
                    )

    if not seen_any:
        problems.append("no Content-Security-Policy found in any nginx config")

    if problems:
        for p in problems:
            print(f"csp-check: {p}", file=sys.stderr)
        return 1

    print(f"csp-check: {len(wanted)} inline script(s) hashed and allowed, policies agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
