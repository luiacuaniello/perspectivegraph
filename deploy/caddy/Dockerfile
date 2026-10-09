# Caddy for the single-VM recipe (docker-compose.vm.yml): built from source with this
# project's Go, on distroless.
#
# Built rather than taken from the official image, because a Caddy release is built once and
# stays as it was built. Twice in one day that left a High in the binary with no newer Caddy
# to move to: 2.11.7's official binary is Go 1.26.8, with two standard-library CVEs
# (CVE-2026-78667 in net/http, CVE-2026-97031 in crypto/tls) that Go 1.26.9 and 1.27.2 fix;
# and Caddy 2.11.7 requires golang.org/x/net v0.59.0, with CVE-2026-78669 (HTTP/2) that
# v0.60.0 fixes. So:
#
#   * the toolchain is the backend's Go, and TestGoVersionIsConsistentEverywhereItIsNamed
#     keeps this pin, and go.mod's, in step with the rest - the standard library is patched
#     whenever this project takes a Go release;
#   * the source is main.go and go.mod beside this file: Caddy's own main package, with
#     go.mod deciding every dependency's version. It requires exactly what Caddy 2.11.7
#     does except where a fix needed more - which Trivy's scan of this image reports in
#     CI - and Dependabot proposes Caddy's releases. go.sum pins every module's hash.
#
# The official image's Alpine userland is gone with it: it carried a High of its own, in zlib.
FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
# Caddy reads its version from the build information of the module that requires it, so
# built this way it reports the release in go.mod.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/caddy . \
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
