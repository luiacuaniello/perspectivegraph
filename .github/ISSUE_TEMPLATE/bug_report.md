---
name: Bug report
about: Something doesn't work as documented
title: "fix: "
labels: bug
---

<!--
Not a bug, a SECURITY problem? Do NOT use this template - report it privately:
https://github.com/luiacuaniello/perspectivegraph/security/advisories/new (see SECURITY.md).
-->

## What happened

A clear description of the bug, and what you expected instead.

## How to reproduce

Steps (smallest path that triggers it):

1.
2.
3.

If it involves ingestion, the source + a minimal sample payload helps a lot.

## Environment

- Deploy: `docker compose` / Helm (k8s) / host dev loop (`make run-backend`)
- Version / commit: <!-- git describe --tags, or the release tag -->
- Graph store: bundled Apache AGE / external Postgres+AGE / in-memory
- OS + Docker/k8s version (if relevant):

## Logs / output

<!-- Relevant backend logs, the failing request/response, or the dashboard error.
     Scrub any secrets (tokens, HMAC secrets, connection strings). -->

```
paste here
```
