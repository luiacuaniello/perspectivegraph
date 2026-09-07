# syntax=docker/dockerfile:1
# PostgreSQL 17 + Apache AGE - the graph database the chart bundles so that
# `helm install` and `docker compose up` work with nothing else in place.
#
# WHY THIS IS BUILT HERE INSTEAD OF PULLING `apache/age`
#
# `apache/age:release_PG17_1.7.0` is not stale - it is the official `postgres:17-trixie`
# image plus the extension, rebuilt in step with it. The problem is the base. Measured
# with Trivy (the same scanner Artifact Hub runs) on 2026-09-07:
#
#   apache/age:release_PG17_1.7.0   406 findings   14 critical
#   postgres:17-trixie              406 findings   14 critical   <- identical, it IS the base
#   postgres:18-trixie (AGE 1.8.0)  406 findings   14 critical   <- a major bump buys nothing
#   postgres:17-alpine               74 findings    1 critical
#
# Thirteen of those fourteen criticals are perl (four packages x three CVEs) and libxml2
# in Debian 13.6, with NO FIX AVAILABLE IN ANY VERSION - they are not waiting on anyone's
# upgrade, and no rebuild of that image will clear them. Alpine does not ship perl at all.
# The fourteenth is Go stdlib inside `gosu`, removed below.
#
# This matters beyond the badge: Artifact Hub's rating is set by the HIGHEST severity
# present and ignores the count entirely (critical=F, high=D, medium=C, low=B), so the
# only thing that moves it is eliminating a severity class, not reducing findings.
FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73 AS build

# Build dependencies live only in this stage; the final image inherits none of them.
RUN apk add --no-cache build-base flex bison perl curl

WORKDIR /src
# The Apache release archive, not a GitHub auto-generated tarball: this one is immutable
# and signed, and its sha512 is published beside it. GitHub's `archive/refs/tags/...`
# tarballs are regenerated on demand and have changed bytes across compression changes,
# which would turn a pinned checksum into a build that breaks for no reason.
ARG AGE_VERSION=1.7.0
ARG AGE_SHA512=301f02088f6828adb8cfa70e7701d9fb541ee9212de97a99f2cf9106e0b0d8bce82f95c20579302bdac5efc3d5ffe35732755b1d093526cec4beba9f30ec82f0
RUN set -eux; \
    curl -fsSL -o age-src.tar.gz \
      "https://archive.apache.org/dist/age/PG17/${AGE_VERSION}/apache-age-${AGE_VERSION}-src.tar.gz"; \
    echo "${AGE_SHA512}  age-src.tar.gz" | sha512sum -c -; \
    tar xzf age-src.tar.gz --strip-components=1; \
    rm age-src.tar.gz

# with_llvm=no is required, not an optimisation. postgres:17-alpine is built --with-llvm,
# so PGXS tries to emit LLVM bitcode for JIT inlining and calls `clang-21`, which is not in
# the image: without this the build dies with "clang-21: No such file or directory" after
# linking age.so successfully. The bitcode only feeds JIT inlining of extension functions;
# the extension itself is complete without it.
RUN make with_llvm=no PG_CONFIG=/usr/local/bin/pg_config \
 && make with_llvm=no PG_CONFIG=/usr/local/bin/pg_config install

# Collect just the installed extension so the final stage copies an exact file set rather
# than a whole filesystem that also contains gcc, the source tree and the object files.
RUN set -eux; \
    mkdir -p "/out$(pg_config --pkglibdir)" "/out$(pg_config --sharedir)/extension"; \
    cp "$(pg_config --pkglibdir)/age.so" "/out$(pg_config --pkglibdir)/"; \
    cp "$(pg_config --sharedir)/extension/age"* "/out$(pg_config --sharedir)/extension/"

FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73

COPY --from=build /out/ /

# Three changes, each of which the scan or the cluster requires:
#
# 1. `apk upgrade` clears the base's own backlog. At the pin above that was 28 findings,
#    every one of them with a fix published - openssl 3.5.7->3.5.8 and libuuid
#    2.42.1->2.42.3. Leaving them would keep this image at a D for packages Alpine had
#    already patched.
#
# 2. `gosu` exists only so the entrypoint can start as root and drop to postgres. This
#    image sets USER below and the chart sets runAsNonRoot, so that branch is never taken
#    and the binary is dead weight - dead weight that carries 46 findings, one of them the
#    only critical left, because it is a Go binary built against the 1.24.6 stdlib and
#    nobody upstream rebuilds it. Removing an unused setuid-style helper is a smaller
#    attack surface, not a quieter scanner. Consequence to know: `docker run --user root`
#    against this image now fails instead of silently dropping privileges.
#
# 3. postgres is uid 70 on Alpine and uid 999 on Debian. Renumbering it to 999 keeps every
#    volume that the previous `apache/age` image wrote readable: PostgreSQL refuses to
#    start when the data directory is not owned by the running user, so without this the
#    image swap would destroy every existing demo database - local compose volumes
#    included - and the failure would look like corruption rather than a uid change.
#    The chown runs BEFORE the rename, while `postgres` still resolves to 70: BusyBox
#    find has -user/-group and no -uid/-gid, so there is no way to select by number once
#    the name no longer points at the old id. gid 999 is already Alpine's `ping` group, so
#    it is dropped first - nothing in the image is group-owned by it (verified with `find
#    -group ping`), and a database image has no use for it. Leaving it would give gid 999
#    two names and hand postgres whatever ping later came to own. The last line is the
#    assertion that all of this landed: the build fails here rather than shipping an image
#    whose postgres is still 70.
RUN set -eux; \
    apk upgrade --no-cache; \
    rm -f /usr/local/bin/gosu; \
    find / -xdev -user postgres -exec chown -h 999 {} +; \
    find / -xdev -group postgres -exec chgrp -h 999 {} +; \
    sed -i '/^ping:x:999:/d' /etc/group; \
    sed -i 's/^postgres:x:70:70:/postgres:x:999:999:/' /etc/passwd; \
    sed -i 's/^postgres:x:70:/postgres:x:999:/' /etc/group; \
    [ "$(id -u postgres):$(id -g postgres)" = "999:999" ]

# Declared, not merely conventional. Kubernetes checks `runAsNonRoot` against the image's
# configured user when the pod does not pin runAsUser, and every image this chart deploys
# leaves it empty - which is to say, root. Setting it here is what lets the database pod
# be admitted to a namespace that enforces the `restricted` Pod Security Standard.
USER postgres
