-- Identity step 10: token introspection (RFC 7662) + revocation (RFC 7009), plan/STEP10-INTROSPECTION.md, lesson 32.

-- Access tokens issued before this moment are reported inactive (set whenever ALL sessions of the person end:
-- block, password change, role removed, deletion, "log out everywhere", stolen refresh token reused)
ALTER TABLE users ADD COLUMN tokens_valid_after TIMESTAMPTZ;

-- Access tokens cancelled one by one (logout). Kept only until the token would have expired anyway.
CREATE TABLE revoked_access_tokens (
    jti        VARCHAR(64)  PRIMARY KEY,
    expires_at TIMESTAMPTZ  NOT NULL
);
CREATE INDEX ix_revoked_access_tokens_expires_at ON revoked_access_tokens (expires_at);
