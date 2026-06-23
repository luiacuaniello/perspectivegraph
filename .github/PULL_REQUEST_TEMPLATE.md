<!--
PR title must follow Conventional Commits (feat:/fix:/docs:/chore:/…) - it's a
required check and drives the changelog. See CONTRIBUTING.md.
-->

## What & why

What does this change, and why? Link any issue (`Closes #123`).

## Checklist

- [ ] PR title follows Conventional Commits (`feat:`, `fix:`, `docs:`, …)
- [ ] Backend: `gofmt`, `go vet`, `go test ./...`, and `gosec` are clean
      (CI runs them; `make test` locally)
- [ ] Frontend (if touched): `tsc`, `npm run build`, and `vitest` pass
- [ ] **Docs + Postman updated** for any user-facing change - the relevant `.md`
      (`README.md` / `ARCHITECTURE.md` / `docs/GUIDA.md` / `.env.example`) **and**
      `docs/perspectivegraph.postman_collection.json`
- [ ] New behavior has tests (and a fuzz test for any new parser)
- [ ] No secrets committed (the `gitleaks` gate enforces it)
- [ ] Didn't weaken the tool's own controls (auth/RBAC, ingest HMAC, audit log,
      at-rest encryption, export signing)

## How was it verified?

Tests added/updated, manual steps, or a `make seed`/`make demo` run - whatever
proves it works.
