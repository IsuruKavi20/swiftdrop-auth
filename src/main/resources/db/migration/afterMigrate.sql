-- Flyway callback: runs after every migrate, as identity_migrator.
-- The app must never read or change Flyway's own bookkeeping table.
REVOKE ALL ON flyway_schema_history FROM identity_app;
