#!/bin/sh
# One backup run: pg_dump (compressed custom format) -> age (encrypt to the PUBLIC key) -> upload, all streamed.
# No unencrypted copy ever touches a disk, and this job can't read or delete backups (write-only storage key).
# Sundays also write a weekly copy. Old copies are removed by the bucket's lifecycle rules, not by this job.
#
# Settings (environment): PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD PGSSLMODE PGSSLROOTCERT,
#   AGE_RECIPIENT (age public key), BACKUP_BUCKET, RCLONE_CONFIG_BACKUP_* (S3-compatible endpoint + write-only key).
set -eu
set -o pipefail

: "${PGHOST:?}" "${PGDATABASE:?}" "${PGUSER:?}" "${PGPASSWORD:?}" "${AGE_RECIPIENT:?}" "${BACKUP_BUCKET:?}"

# Date + time (UTC): the storage key may only CREATE files, never overwrite, so a retry needs a new name
stamp=$(date -u +%Y-%m-%dT%H%M%SZ)

upload() {
    target="backup:${BACKUP_BUCKET}/$1/${stamp}.dump.age"
    # --no-check-bucket / --no-head: the key may only CREATE objects, never list or read them.
    # One single PUT (cutoff far above our size): a multipart upload would need more rights.
    pg_dump --format=custom --no-password \
        | age --encrypt --recipient "${AGE_RECIPIENT}" \
        | rclone rcat --s3-no-check-bucket --s3-no-head --streaming-upload-cutoff 256M "${target}"
    echo "Backup uploaded: $1/${stamp}.dump.age"
}

upload daily
if [ "$(date -u +%u)" = "7" ]; then
    upload weekly
fi

# Identity step 8: the ids of everyone deleted (finished erasures + tombstones still waiting), as CSV, also locked.
# After restoring an older backup, deploy/oke/reapply-erasures.ps1 deletes these people again. Ids and dates only.
erasures="backup:${BACKUP_BUCKET}/erasures/${stamp}.csv.age"
psql --no-password --quiet -v ON_ERROR_STOP=1 -c "COPY (
        SELECT user_id, deleted_at FROM identity.erasure_log
        UNION SELECT id, deleted_at FROM identity.users WHERE status = 'DELETED'
    ) TO STDOUT WITH CSV" \
    | age --encrypt --recipient "${AGE_RECIPIENT}" \
    | rclone rcat --s3-no-check-bucket --s3-no-head --streaming-upload-cutoff 256M "${erasures}"
echo "Erasure list uploaded: erasures/${stamp}.csv.age"
