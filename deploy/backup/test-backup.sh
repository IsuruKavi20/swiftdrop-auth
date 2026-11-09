#!/usr/bin/env bash
# End-to-end test of the backup image on this machine (Docker): a real Postgres with test data, rclone's own S3
# server as the object storage, one backup run, then download + decrypt with the PRIVATE key + pg_restore.
# Proves a backup can really be restored. Run from the repo root: bash deploy/backup/test-backup.sh
# Everything it creates is removed again at the end (containers, network, temp files, the test image).
set -euo pipefail

net=backup-test-$$
image=swiftdrop-backup:test
work=$(mktemp -d)

cleanup() {
    docker rm -f "pg-$net" "s3-$net" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    docker rmi "$image" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# Test-only admin access to the fake storage (create the bucket, read the result back)
rc() {
    docker run --rm -i --network "$net" \
        -e RCLONE_CONFIG=/tmp/rclone.conf \
        -e RCLONE_CONFIG_S_TYPE=s3 -e RCLONE_CONFIG_S_PROVIDER=Rclone \
        -e RCLONE_CONFIG_S_ENDPOINT="http://s3-$net:9000" \
        -e RCLONE_CONFIG_S_ACCESS_KEY_ID=testkey -e RCLONE_CONFIG_S_SECRET_ACCESS_KEY=testsecret123 \
        -e RCLONE_CONFIG_S_FORCE_PATH_STYLE=true \
        --entrypoint rclone "$image" "$@"
}

docker build -q -t "$image" deploy/backup >/dev/null
docker network create "$net" >/dev/null
docker run -d --name "pg-$net" --network "$net" -e POSTGRES_PASSWORD=admin -e POSTGRES_DB=identity \
    docker.io/library/postgres:17-alpine >/dev/null
# Fake S3 storage: rclone's S3 server, from the same image (no extra download)
docker run -d --name "s3-$net" --network "$net" --entrypoint rclone "$image" \
    serve s3 --addr :9000 --auth-key testkey,testsecret123 /tmp/data >/dev/null

until docker exec "pg-$net" pg_isready -U postgres -d identity >/dev/null 2>&1; do sleep 1; done
sleep 2

# Test data + the read-only role the job uses
docker exec -i "pg-$net" psql -q -U postgres -d identity <<'SQL'
CREATE SCHEMA identity;
CREATE TABLE identity.users (id int PRIMARY KEY, email text);
INSERT INTO identity.users SELECT g, 'user' || g || '@example.com' FROM generate_series(1, 25) g;
CREATE ROLE backup_reader LOGIN PASSWORD 'readerpw';
GRANT CONNECT ON DATABASE identity TO backup_reader;
GRANT pg_read_all_data TO backup_reader;
ALTER ROLE backup_reader SET default_transaction_read_only = on;
SQL
until rc mkdir s:swiftdrop-auth-backups >/dev/null 2>&1; do sleep 1; done

# A throwaway key pair (production: the private key exists only on Isuru's side)
docker run --rm --entrypoint age-keygen "$image" 2>/dev/null > "$work/key.txt"
public=$(grep -o 'age1[0-9a-z]*' "$work/key.txt")

# The real backup run, locked down like in the cluster (read-only filesystem, only /tmp writable)
docker run --rm --network "$net" --read-only --tmpfs /tmp \
    -e PGHOST="pg-$net" -e PGDATABASE=identity -e PGUSER=backup_reader -e PGPASSWORD=readerpw -e PGSSLMODE=disable \
    -e AGE_RECIPIENT="$public" -e BACKUP_BUCKET=swiftdrop-auth-backups -e RCLONE_CONFIG=/tmp/rclone.conf \
    -e RCLONE_CONFIG_BACKUP_TYPE=s3 -e RCLONE_CONFIG_BACKUP_PROVIDER=Rclone \
    -e RCLONE_CONFIG_BACKUP_ENDPOINT="http://s3-$net:9000" \
    -e RCLONE_CONFIG_BACKUP_ACCESS_KEY_ID=testkey -e RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY=testsecret123 \
    -e RCLONE_CONFIG_BACKUP_FORCE_PATH_STYLE=true \
    "$image"

file=$(rc lsf s:swiftdrop-auth-backups/daily/)
echo "In storage: daily/$file"
rc cat "s:swiftdrop-auth-backups/daily/$file" > "$work/backup.age"

# Encrypted for real: no readable email address inside
if grep -q "example.com" "$work/backup.age"; then echo "FAIL: backup is not encrypted"; exit 1; fi
echo "Encrypted: no readable data inside"

# Restore: decrypt with the private key, load into a fresh database, count the users
docker exec "pg-$net" psql -q -U postgres -c "CREATE DATABASE restored"
# (the backup streams in on stdin and the key as a variable: no folder sharing, so it works on Windows too)
docker run --rm -i -e AGE_KEY="$(cat "$work/key.txt")" --entrypoint sh "$image" \
        -c 'printf "%s\n" "$AGE_KEY" > /tmp/key && age --decrypt -i /tmp/key' < "$work/backup.age" \
    | docker exec -i "pg-$net" pg_restore -U postgres -d restored
count=$(docker exec "pg-$net" psql -tA -U postgres -d restored -c "SELECT count(*) FROM identity.users")
if [ "$count" = "25" ]; then echo "PASS: backup restored, 25 of 25 users back"; else echo "FAIL: restored $count users"; exit 1; fi
