# syntax=docker/dockerfile:1
# Build the dashboard and serve the static assets with nginx. A default nginx
# config (SPA routing + /graphql proxy to the backend) is baked in so the image
# runs standalone under docker compose; in Kubernetes the Helm chart mounts its
# own config over it.

FROM node:22-alpine@sha256:9385cd9f3001dfc3431e8ead12c43e9e1f87cc1b9b5c6cfd0f73865d405b27c4 AS build
WORKDIR /app
COPY package*.json ./
# `npm install` (not `npm ci`) on purpose: the lockfile pins platform-specific
# native deps (rolldown/esbuild bindings), and a lock generated on macOS lacks
# the Linux variants — which would make `npm ci` here fail and silently ship a
# stale image. `install` resolves correctly regardless of where the lock was made.
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.31.1-alpine@sha256:8b1e78743a03dbb2c95171cc58639fef29abc8816598e27fb910ed2e621e589a
# Base is pinned by digest for reproducibility; apk upgrade patches any OS-package
# CVEs disclosed since that digest was built (e.g. openssl/libxml2), so the image
# stays current without waiting on a base rebuild. Keeps the Trivy CI gate green.
RUN apk upgrade --no-cache
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["wget", "-q", "-O", "-", "http://127.0.0.1/"]
