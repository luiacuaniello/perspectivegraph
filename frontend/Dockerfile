# syntax=docker/dockerfile:1
# Build the dashboard and serve the static assets with nginx. A default nginx
# config (SPA routing + /graphql proxy to the backend) is baked in so the image
# runs standalone under docker compose; in Kubernetes the Helm chart mounts its
# own config over it.

# --platform=$BUILDPLATFORM pins this stage to the RUNNER's architecture, not the
# target's. The output of `npm run build` is JavaScript, CSS and HTML - it has no
# architecture - so emulating the whole Node toolchain under QEMU to produce arm64
# assets buys nothing and costs hours: vite/rolldown are native Rust binaries, and
# emulated they crawl. Only the nginx stage below varies per target.
#
# This line is the only place Node is named. CI's setup-node and `make lockfile` read it
# through scripts/node-image.sh, so the bump Dependabot proposes here is complete. The tag
# is the exact version, not `24-alpine`: a floating tag moves the Node version under an
# unchanged-looking line, and nothing reading it could say which Node it is.
FROM --platform=$BUILDPLATFORM node:24.21.0-alpine@sha256:be80f76cf40ec8e42b9bec49f60a55e0660f30af58d3e5a25530785b30ea67e2 AS build
WORKDIR /app
COPY package*.json ./
# `npm ci`, never `npm install`: it installs exactly what package-lock.json pins and
# fails rather than resolving anything new, so this image is reproducible and the SBOM
# and SLSA provenance attached to it describe what is actually inside. `npm install`
# would quietly resolve unpinned transitives at build time, which is not a supply chain
# a consumer can verify.
#
# The lockfile must therefore be complete for linux/amd64 and linux/arm64. npm only
# records the transitive dependencies of optional platform packages for the platform it
# runs on, so a lockfile regenerated on macOS drops entries this build needs and `npm
# ci` fails here loudly. Regenerate it with `make lockfile`, which runs npm in this same
# image rather than on the developer's machine.
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.31.5-alpine@sha256:72ba65eb42c10344912a84ff42408db7d34f2feb642204570ab8fc5ffd29f1d3
# Base is pinned by digest for reproducibility; apk upgrade patches any OS-package
# CVEs disclosed since that digest was built (e.g. openssl/libxml2), so the image
# stays current without waiting on a base rebuild. Keeps the Trivy CI gate green.
# We also drop curl + its dependency chain (libcurl/nghttp2/c-ares/…): this is a
# static-file server (nginx serves the built SPA) and the healthcheck uses wget,
# so curl is unused weight - and removing it clears CVEs in curl that alpine has
# no fixed version for yet, shrinking the attack surface instead of carrying them.
RUN apk upgrade --no-cache && apk del curl
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["wget", "-q", "-O", "-", "http://127.0.0.1/"]
