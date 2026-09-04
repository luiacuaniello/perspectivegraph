# syntax=docker/dockerfile:1
# Multi-stage build producing a tiny static PerspectiveGraph binary.

# --platform=$BUILDPLATFORM keeps the compiler on the RUNNER's architecture and lets Go
# cross-compile to the target, which it does natively with CGO already off. Emulating the
# toolchain under QEMU would produce the same static binary far slower - and emulation is
# not merely slow: `npm ci` under QEMU/arm64 died with SIGILL and hung a release build for
# three hours (see frontend/Dockerfile). Nothing here needs to run on the target.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
# Supplied by buildx per target image; defaulted so a plain `docker build` still works.
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled → fully static binary (pure-Go resolver), runs on distroless.
# Build cache mounts keep rebuilds fast without bloating the image.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/perspectivegraph ./cmd/perspectivegraph

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/perspectivegraph /perspectivegraph
EXPOSE 8080 8081
USER nonroot:nonroot
# The binary self-checks via its `healthz` subcommand (distroless has no shell).
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["/perspectivegraph", "healthz"]
ENTRYPOINT ["/perspectivegraph"]
