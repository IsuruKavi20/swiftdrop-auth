-- Identity step 9a: the audit log (plan/STEP9-ADMIN-AUDIT.md, lesson 30). Who did what to whom, and when.
-- Ids only, never emails or names. Tamper-evident: each row's hash covers the previous row's hash (a chain).
CREATE TABLE audit_log (
    seq         BIGSERIAL     PRIMARY KEY,
    at          TIMESTAMPTZ   NOT NULL,
    actor_type  VARCHAR(12)   NOT NULL CHECK (actor_type IN ('USER', 'SERVICE', 'SYSTEM', 'BREAK_GLASS')),
    actor_id    VARCHAR(80),
    action      VARCHAR(60)   NOT NULL,
    target_type VARCHAR(30),
    target_id   VARCHAR(80),
    ip          VARCHAR(45),
    request_id  VARCHAR(64),
    details     TEXT          NOT NULL,   -- JSON, kept as TEXT: the exact bytes the hash covers
    prev_hash   CHAR(64)      NOT NULL,
    hash        CHAR(64)      NOT NULL
);
CREATE INDEX ix_audit_log_at ON audit_log (at);
CREATE INDEX ix_audit_log_actor ON audit_log (actor_id, seq);
CREATE INDEX ix_audit_log_target ON audit_log (target_id, seq);

-- Where the chain starts: after the yearly clean-up removes the oldest rows, the hash of the last removed row
CREATE TABLE audit_checkpoint (
    id   SMALLINT  PRIMARY KEY CHECK (id = 1),
    seq  BIGINT    NOT NULL,
    hash CHAR(64)  NOT NULL
);
INSERT INTO audit_checkpoint (id, seq, hash) VALUES (1, 0, repeat('0', 64));

-- Append-only, in two layers. 1) The app's role can never change a row (the clean-up may only remove old ones).
REVOKE UPDATE, TRUNCATE ON audit_log FROM identity_app;
REVOKE INSERT, DELETE, TRUNCATE ON audit_checkpoint FROM identity_app;

-- 2) A trigger refuses changes for EVERY role, and removing a row younger than one year
CREATE FUNCTION audit_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.at < now() - interval '365 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard();
