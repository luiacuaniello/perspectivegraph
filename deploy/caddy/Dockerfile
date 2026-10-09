# Caddy for the single-VM recipe (docker-compose.vm.yml): the official binary, on distroless.
#
# The official image is Alpine, and its userland - apk, curl, zlib - is where scanners find
# things: on 2026-10-09 caddy:2.11.7-alpine carried a High in zlib, which Caddy, a static
# Go binary, never loads. The backend runs on this same base for the same reason. What is
# left is the binary, CA certificates and the nonroot user.
#
# The binary is copied with `cp` in a RUN rather than straight across: upstream gives it
# cap_net_bind_service as a file capability, and under the compose file's cap_drop ALL a
# binary carrying one cannot be executed at all ("exec /usr/bin/caddy: operation not
# permitted", measured). It needs no capability: Docker lets any process bind ports below
# 1024 inside its own network namespace (net.ipv4.ip_unprivileged_port_start=0).
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f AS upstream
RUN cp /usr/bin/caddy /caddy && mkdir -p /out/data /out/config

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=upstream /caddy /usr/bin/caddy
# The certificates and the ACME account key live in /data, a volume in the compose file. An
# empty volume takes the owner of the directory it is mounted over, so these two make it
# writable by the nonroot user without an init container.
COPY --from=upstream --chown=65532:65532 /out/data /data
COPY --from=upstream --chown=65532:65532 /out/config /config
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
USER nonroot:nonroot
EXPOSE 80 443 443/udp
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
