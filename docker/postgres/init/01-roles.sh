#!/bin/sh
# Runs once, as the superuser, when the Postgres volume is first created.
# Creates a schema-owner role for Flyway and a DML-only role for the application (least privilege).
# DEV ONLY: passwords arrive as container env vars. Production uses Docker secrets / a vault.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v migrator_password="$DB_MIGRATOR_PASSWORD" \
    -v app_password="$DB_APP_PASSWORD" \
    -v db_name="$POSTGRES_DB" <<'EOSQL'
CREATE ROLE identity_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE identity_app LOGIN PASSWORD :'app_password';
ALTER ROLE identity_migrator SET search_path = identity;
ALTER ROLE identity_app SET search_path = identity;

-- Nobody gets anything by default: no connect, no temp tables, no use of the public schema
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO identity_migrator, identity_app;

CREATE SCHEMA identity AUTHORIZATION identity_migrator;
GRANT USAGE ON SCHEMA identity TO identity_app;

-- Every table/sequence Flyway creates later is usable (rows only) by the app
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identity_app;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity
    GRANT USAGE, SELECT ON SEQUENCES TO identity_app;
-- Functions are not callable by everyone; grant them one by one if ever needed
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
EOSQL
