# Caddy for the single-VM recipe (docker-compose.vm.yml): built from source with this
# project's Go, on distroless.
#
# Built rather than taken from the official image, for the Go it is compiled with. A Caddy
# release is built once, with the Go of its day, and stays that way: 2.11.7's binary is Go
# 1.26.8, and Trivy finds two High standard-library CVEs in it (CVE-2026-78667 in net/http,
# CVE-2026-97031 in crypto/tls) that 1.26.9 and 1.27.2 fix - on 2026-10-09, with no newer
# Caddy to move to. Compiled here with the toolchain the backend uses, the binary takes the
# standard library's fixes whenever this project takes a Go release, and
# TestGoVersionIsConsistentEverywhereItIsNamed keeps this pin in step with the rest.
#
# The source is Caddy's tagged release through the Go module proxy, every module checked
# against the checksum database (sum.golang.org), so what is built is what the tag names.
# The official image's Alpine userland is gone with it: it carried a High of its own, in zlib.
#
# To move to a new Caddy release, change CADDY_VERSION - Dependabot does not watch it.
#
# Built for the machine it runs on (compose builds it there), so natively: `go install`
# refuses an install directory for a cross-compiled binary. CustomVersion is how Caddy lets
# a packager name the release: built as the main module, it would otherwise report
# "unknown".
FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build
ARG CADDY_VERSION=v2.11.7
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOBIN=/out \
    go install -trimpath \
      -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=${CADDY_VERSION}" \
      "github.com/caddyserver/caddy/v2/cmd/caddy@${CADDY_VERSION}" \
 && mkdir -p /out/data /out/config

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/caddy /usr/bin/caddy
# The certificates and the ACME account key live in /data, a volume in the compose file. An
# empty volume takes the owner of the directory it is mounted over, so these two make it
# writable by the nonroot user without an init container. Caddy needs no capability for
# ports 80 and 443: Docker lets any process bind ports below 1024 inside its own network
# namespace (net.ipv4.ip_unprivileged_port_start=0), which is why the compose file can drop
# them all.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/config /config
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
USER nonroot:nonroot
EXPOSE 80 443 443/udp
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
