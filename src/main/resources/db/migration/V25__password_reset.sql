-- Identity step 11a: forgot password (plan/STEP11-MFA-RESET-MONITORING.md, lesson 33).
-- One-time reset links. Only the SHA-256 hash of a token is stored, never the token. 30 minutes, single use.
CREATE TABLE password_reset_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uk_password_reset_tokens_hash UNIQUE (token_hash),
    CONSTRAINT ck_password_reset_tokens_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_password_reset_tokens_user_created ON password_reset_tokens (user_id, created_at);
CREATE INDEX ix_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);
