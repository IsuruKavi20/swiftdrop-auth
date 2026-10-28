-- Google login (Step 12).

-- One Google account per user (and, from V1, one user per Google account)
ALTER TABLE oauth_accounts
    ADD CONSTRAINT uk_oauth_accounts_user_provider UNIQUE (user_id, provider);

-- One-time hand-off codes: after Google login the browser gets this code (60 s) and swaps it for our tokens.
-- Only the SHA-256 hash is stored.
CREATE TABLE login_handoff_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   VARCHAR(64) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    -- base64url(SHA-256(verifier)) from the browser that started the login (login-CSRF defence)
    browser_challenge VARCHAR(43) NOT NULL,
    CONSTRAINT uk_login_handoff_codes_hash UNIQUE (code_hash),
    CONSTRAINT ck_login_handoff_codes_challenge CHECK (browser_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT ck_login_handoff_codes_hash_hex CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_login_handoff_codes_expiry CHECK (expires_at > created_at)
);

CREATE INDEX ix_login_handoff_codes_user_id ON login_handoff_codes (user_id);

-- A pre-hijacked account reclaimed through Google ends the attacker's sessions with this reason
ALTER TABLE refresh_tokens DROP CONSTRAINT ck_refresh_tokens_reason;
ALTER TABLE refresh_tokens ADD CONSTRAINT ck_refresh_tokens_reason
    CHECK (revoke_reason IN ('LOGOUT', 'REUSE_DETECTED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED', 'ACCOUNT_RECLAIMED'));
