# syntax=docker/dockerfile:1
# Multi-stage build producing a tiny static PerspectiveGraph binary.

FROM golang:1.25.11-alpine@sha256:8d95af53d0d58e1759ddb4028285d9b1239067e4fbf4f544618cad0f60fbc354 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled → fully static binary (pure-Go resolver), runs on distroless.
# Build cache mounts keep rebuilds fast without bloating the image.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/perspectivegraph ./cmd/perspectivegraph

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/perspectivegraph /perspectivegraph
EXPOSE 8080 8081
USER nonroot:nonroot
# The binary self-checks via its `healthz` subcommand (distroless has no shell).
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["/perspectivegraph", "healthz"]
ENTRYPOINT ["/perspectivegraph"]
