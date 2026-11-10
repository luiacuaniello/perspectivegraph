# syntax=docker/dockerfile:1
# Multi-stage build producing a tiny static PerspectiveGraph binary.

# --platform=$BUILDPLATFORM keeps the compiler on the RUNNER's architecture and lets Go
# cross-compile to the target, which it does natively with CGO already off. Emulating the
# toolchain under QEMU would produce the same static binary far slower - and emulation is
# not merely slow: `npm ci` under QEMU/arm64 died with SIGILL and hung a release build for
# three hours (see frontend/Dockerfile). Nothing here needs to run on the target.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
# Supplied by buildx per target image; defaulted so a plain `docker build` still works.
ARG TARGETOS=linux
ARG TARGETARCH
# The release this image is, linked into the binary so that it can say so: in `version`,
# in the first line of its log, in perspectivegraph_build_info, and to an MCP client. The
# release workflow passes the tag; any other build leaves it empty and says "dev".
ARG VERSION=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled → fully static binary (pure-Go resolver), runs on distroless.
# Build cache mounts keep rebuilds fast without bloating the image.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.releaseVersion=${VERSION}" -o /out/perspectivegraph ./cmd/perspectivegraph

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/perspectivegraph /perspectivegraph
EXPOSE 8080 8081
USER nonroot:nonroot
# The binary self-checks via its `healthz` subcommand (distroless has no shell).
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["/perspectivegraph", "healthz"]
ENTRYPOINT ["/perspectivegraph"]
# The same image is the MCP server (`docker run -i --rm <image> mcp --api <url>`), and the
# official MCP Registry verifies that an image belongs to the entry listing it by reading
# this label: its value must equal the `name` in that entry. Without it the image cannot
# be listed at all, so it ships in every release rather than being added at publish time.
LABEL io.modelcontextprotocol.server.name="io.github.luiacuaniello/perspectivegraph"
