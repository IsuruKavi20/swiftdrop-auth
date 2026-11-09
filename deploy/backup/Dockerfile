# Nightly backup job image (plan/STEP-BACKUPS.md): Postgres 17 client + age (encryption) + rclone (upload).
# Same Postgres major version as the database, so pg_dump always matches. Multi-arch (x86 + ARM) via CI.
FROM docker.io/library/postgres:17-alpine
RUN apk add --no-cache age rclone
COPY --chmod=0555 backup.sh /usr/local/bin/backup.sh
# The image's "postgres" user (70); never root
USER 70:70
ENTRYPOINT ["/usr/local/bin/backup.sh"]
