#!/bin/sh
# The read-only role used by the nightly backup job (plan/STEP-BACKUPS.md). Runs automatically when a new database is
# created; on an EXISTING database run it once by hand (lesson 28). Safe to run again: it then only resets the password.
# Does nothing when DB_BACKUP_PASSWORD is not set (backups switched off, or docker-compose on a laptop).
set -eu
[ -n "${DB_BACKUP_PASSWORD:-}" ] || { echo "02-backup-role: no DB_BACKUP_PASSWORD, skipped"; exit 0; }

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "$POSTGRES_DB" <<'EOSQL'
\getenv backup_password DB_BACKUP_PASSWORD
\getenv db_name POSTGRES_DB
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'backup_reader') AS missing \gset
\if :missing
CREATE ROLE backup_reader LOGIN PASSWORD :'backup_password';
\else
ALTER ROLE backup_reader PASSWORD :'backup_password';
\endif
-- Reads everything, changes nothing
GRANT CONNECT ON DATABASE :"db_name" TO backup_reader;
GRANT pg_read_all_data TO backup_reader;
ALTER ROLE backup_reader SET default_transaction_read_only = on;
EOSQL
