# Release checklist — MVP → public demo

Status legend: items checked are done in the working tree and only need to be committed.

## 0. Done in the working tree (commit these)

- [x] Pin Apache AGE docker image to an existing tag (`release_PG16_1.6.0`) — `PG16_latest` was removed from Docker Hub (docker-compose.yml, helm values)
- [x] AGE store parity with the in-memory reference: property merge on `UpsertNode` (shared `graph.MergeProps`), explicit error + broker redelivery for edges whose endpoints are not in the graph yet
- [x] Store contract test suite that runs against **both** implementations (in-memory always, AGE when Postgres is reachable, on an isolated graph)
- [x] Frontend redesign: sidebar navigation (Overview / Attack paths / Graph / Violations / Search), attack-path detail with kill chain + generated remediations, policy violations view
- [x] Graph canvas no longer rebuilt on every poll (pan/zoom preserved); dangling edges filtered before Cytoscape
- [x] OpenSearch integrated end-to-end: `make up-search` target, full-text Search view in the dashboard, README aligned (quick start no longer claims `make up` boots OpenSearch)
- [x] Helm chart verified on a real cluster (docker-desktop): `helm lint` clean, external-endpoint guards behave, full deploy of backend/frontend/Postgres+AGE/NATS, seed + GraphQL through the frontend's nginx proxy all green. Publishing prerequisite: `docker push` both images to `ghcr.io/luiacuaniello/*` (and make the packages public) so `helm install` works without a local build

## 1. Blockers — do before the first push

- [x] **GitHub account vs module path**: module is `github.com/luiacuaniello/perspectivegraph` and images are `ghcr.io/luiacuaniello/*` — matches the publishing account. One manual step left: **name the GitHub repo exactly `perspectivegraph`**, or `go install` and the documented docker builds break
- [x] Add `.claude/` to `.gitignore` (local tooling config)
- [x] README accuracy pass: "five sources", *Project status* refreshed (search UI, store-parity contract tests, dashboard sections)
- [x] Makefile `seed` help text updated (five sources → six ranked attack paths)
- [x] README screenshots: `docs/screenshot-overview.png` + `docs/screenshot-paths.png` (dashboard supports `#view` deep links, e.g. `/#paths`)
- [x] Helm external endpoints implemented: `postgres.externalHost`/`externalPort` and `nats.externalUrl` (with `required` guards when the bundled component is disabled); README deploy section documents them
- [x] `.env.example` now accurate: `loadDotEnv` reads `.env` from the working directory **and** its parent, so `make run-backend` picks up the repo-root file
- [x] Fresh-stack smoke test passed (volumes wiped → `make up` → backend with pure defaults → seed → 6 paths / 2 runtime-confirmed on AGE); CI commands green locally (`go build/vet/test` ×11 pkgs, `npm ci && npm run build`)
- [x] Secret scan of the tree (only fake tokens in tests; `.env` is gitignored)

## 2. Hardening — soon after publishing

- [x] NATS consumer: `MaxDeliver=8` + per-attempt backoff (1s→1m via `NakWithDelay`); poison events are Terminated after the cap instead of redelivering forever
- [x] `subjectFor` hardened: the configured subject is a base (legacy `.*`/`.>` suffixes accepted), the stream binds `base.>`, and source tokens are sanitized (`my.scanner` → `my-scanner`) — verified live: dotted sources ingest fine
- [x] `ANALYZER_INTERVAL` validated in config (non-positive/malformed → default) plus a defensive guard in `analyzer.NewService`
- [x] GitHub & GitLab commenters paginate the marker search (up to 2,000 comments); restart-dedupe rides the forge-side marker comment (find → update), the in-memory hash only skips redundant API calls
- [x] OpenSearch `_bulk`: per-item `errors` parsed; partial failures now return an error with the count and first reason
- [x] Falco decoder: streaming `json.Decoder` handles compact, pretty-printed, NDJSON and concatenated objects (test added)
- [x] `NormalizeImageRef` converges `nginx:1.25` ≡ `library/nginx:1.25` ≡ `docker.io/library/nginx:1.25` (and strips `localhost/`)
- [x] Dangling-edge contract decided: **both** stores reject edges with missing endpoints; the broker's redelivery turns it into eventual consistency (encoded in the contract tests, proven live: edge-only event retried with backoff, landed once its nodes arrived)

## 3. Demo → product (architecture)

- [x] Custodian reads **real AWS export shapes** (Tags/TagList, `AttachedManagedPolicies`, `PublicIpAddress`, `Scheme`, ACL AllUsers grants, `PubliclyAccessible`); crown-jewel classification is **data-driven via resource tags** (`ingestion.CrownJewelFromTags`); LB→EC2 inferred from the shared `app` tag, admin-role reach inferred from AdministratorAccess — same demo topology, zero invented fields
- [x] New **build-provenance collector** (`POST /ingest/build`): a CI step posts image↔repository and the Image --BUILT_FROM--> Repository edge connects SAST findings without the hand-fed context (wired into `make seed` and the Postman collection)
- [x] One severity→probability scale (`ingestion.SeverityProbability`); trivy and semgrep map through it (semgrep keeps its confidence discount on top)
- [x] Remediation is a **rule registry** (`remediation.Registry`) + a hint registry (`remediation.Hints`) that the PR commenter renders — the parallel switch in the commenter is gone
- [x] GraphQL: `attackPaths(app, limit)`, `graph(app, limit, offset)` with connected-component scoping, `applications` listing; **one snapshot per request** (context-memoized loader); analyzer **change-detection** via `graph.VersionedStore` (verified: zero passes in 31s of idle that previously ran 3)
- [x] Multi-application dashboard: header selector (All applications / repo slugs / app tags) scoping paths + graph; posture stays environment-wide by design
- [x] Dead code & duplication removed: `Normalizer.Alias`, `Engine.Add`, unreachable `events` guard, fake schema assertion, the 7 resolver clones (one generic `field[T]`), and `requestJSON`/`search.do` now share `internal/httpx`

## 4. OSS repo polish

- [ ] CI badge in the README
- [x] `SECURITY.md` with a responsible-disclosure policy (it is a security tool — expected)
- [x] Update the roadmap checkboxes in `ARCHITECTURE.md` — kept current (store-parity, search UI, dark mode, ATT&CK, the A/B hardening blocks)
- [x] Frontend tests in CI — the frontend job now runs **Vitest** + `npm audit` (not just build). Still open: an **ESLint** step and **code-splitting** the ~666 kB bundle (lazy-load Cytoscape)
- [ ] GitHub side (manual): repo description, topics, issue templates, `v0.1.0` tag with the first push
