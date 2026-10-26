-- One-time email verification tokens. Only the SHA-256 hash of a token is stored, never the token.
CREATE TABLE email_verification_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uk_email_verification_tokens_hash UNIQUE (token_hash),
    CONSTRAINT ck_email_verification_tokens_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_email_verification_tokens_user_id ON email_verification_tokens (user_id);
