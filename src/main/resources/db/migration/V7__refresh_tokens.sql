-- Refresh tokens (RFC 9700 4.14): opaque, rotated on every use, only the SHA-256 hash stored.
-- All tokens from one login share a family_id; reuse of a used token revokes the whole family.
CREATE TABLE refresh_tokens (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id         UUID        NOT NULL,
    token_hash        VARCHAR(64) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,   -- idle limit, never beyond family_expires_at
    family_expires_at TIMESTAMPTZ NOT NULL,   -- absolute limit of the whole session
    used_at           TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revoke_reason     VARCHAR(30),
    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT ck_refresh_tokens_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_refresh_tokens_expiry CHECK (expires_at <= family_expires_at AND family_expires_at > created_at),
    CONSTRAINT ck_refresh_tokens_used CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT ck_refresh_tokens_revoked CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    CONSTRAINT ck_refresh_tokens_reason
        CHECK (revoke_reason IN ('LOGOUT', 'REUSE_DETECTED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED'))
);

-- Safety net: a session can never fork into two live tokens, whatever the application code does
CREATE UNIQUE INDEX uk_refresh_tokens_live_family ON refresh_tokens (family_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens (family_id);
CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_family_expires_at ON refresh_tokens (family_expires_at);
