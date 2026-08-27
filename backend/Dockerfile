# syntax=docker/dockerfile:1
# Multi-stage build producing a tiny static PerspectiveGraph binary.

# --platform=$BUILDPLATFORM keeps the compiler on the RUNNER's architecture and lets Go
# cross-compile to the target, which it does natively with CGO already off. Emulating the
# toolchain under QEMU would produce the same static binary far slower - and emulation is
# not merely slow: `npm ci` under QEMU/arm64 died with SIGILL and hung a release build for
# three hours (see frontend/Dockerfile). Nothing here needs to run on the target.
FROM --platform=$BUILDPLATFORM golang:1.26.7-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/perspectivegraph /perspectivegraph
EXPOSE 8080 8081
USER nonroot:nonroot
# The binary self-checks via its `healthz` subcommand (distroless has no shell).
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["/perspectivegraph", "healthz"]
ENTRYPOINT ["/perspectivegraph"]
