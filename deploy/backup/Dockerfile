# Nightly backup job image (plan/STEP-BACKUPS.md): Postgres 17 client + age (encryption) + rclone (upload).
#
# age and rclone are compiled here with the newest Go: distribution packages lag behind and carried known Go
# vulnerabilities (Trivy, 2026-11-09). The final image is plain Alpine with only the Postgres CLIENT: no database
# server and no gosu, so less to patch. Versions are pinned; Dependabot/Trivy show when to bump them.
# Cross-compiled on the build machine for each target CPU (x86 + ARM): no slow emulated compiling.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-alpine3.24 AS tools
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-trimpath
RUN go install -ldflags="-s -w" filippo.io/age/cmd/age@v1.3.2 \
 && go install -ldflags="-s -w" filippo.io/age/cmd/age-keygen@v1.3.2 \
 && go install -ldflags="-s -w" github.com/rclone/rclone@v1.76.0 \
 && mkdir /out && find /go/bin -type f \( -name age -o -name age-keygen -o -name rclone \) -exec cp {} /out/ \;

FROM docker.io/library/alpine:3.24
# The Postgres 17 client (pg_dump, pg_restore, psql): same major version as the database
RUN apk add --no-cache postgresql17-client ca-certificates tzdata
COPY --from=tools /out/ /usr/local/bin/
COPY --chmod=0555 backup.sh /usr/local/bin/backup.sh
USER 70:70
ENTRYPOINT ["/usr/local/bin/backup.sh"]
