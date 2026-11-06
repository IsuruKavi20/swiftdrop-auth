-- Identity step 3e: "delete my account" turns the row into a tombstone (design doc section 7, step 1).
-- The tombstone keeps only the id (+ when) for 30 days, so SwiftDrop can finish its part; step 8 hard-deletes.
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'DELETED')),
    -- A deleted account always says when; a living one never does
    ADD CONSTRAINT ck_users_deleted_at CHECK ((status = 'DELETED') = (deleted_at IS NOT NULL));

ALTER TABLE refresh_tokens DROP CONSTRAINT ck_refresh_tokens_reason;
ALTER TABLE refresh_tokens ADD CONSTRAINT ck_refresh_tokens_reason
    CHECK (revoke_reason IN ('LOGOUT', 'REUSE_DETECTED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED', 'ACCOUNT_RECLAIMED',
                             'EMAIL_CHANGE_UNDONE', 'PASSWORD_CHANGED', 'ACCOUNT_DELETED'));
