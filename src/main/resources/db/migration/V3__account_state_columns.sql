-- Account state needed for email verification, lockout and auditing, plus optimistic locking.
ALTER TABLE users
    ADD COLUMN email_verified     BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN failed_login_count INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN locked_until       TIMESTAMPTZ,
    ADD COLUMN last_login_at      TIMESTAMPTZ,
    ADD COLUMN updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN version            BIGINT      NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_users_failed_login_count CHECK (failed_login_count >= 0);

-- Postgres does not index foreign keys automatically; ON DELETE CASCADE and
-- "find this user's Google link" both look up oauth_accounts by user_id.
CREATE INDEX ix_oauth_accounts_user_id ON oauth_accounts (user_id);
