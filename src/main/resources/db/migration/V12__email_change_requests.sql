-- Login email changes (identity step 3b). A change only happens after the NEW address confirms; the OLD address
-- gets a notice and, after the change, an undo link. Only SHA-256 hashes of link tokens are stored.
CREATE TABLE email_change_requests (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    old_email          VARCHAR(320) NOT NULL,
    new_email          VARCHAR(320) NOT NULL,
    -- Set when the confirmation email is sent (asynchronously, through the outbox)
    confirm_token_hash VARCHAR(64),
    confirm_expires_at TIMESTAMPTZ  NOT NULL,
    confirmed_at       TIMESTAMPTZ,
    -- Set at confirmation: the old address's undo link (step 3b-3)
    revert_token_hash  VARCHAR(64),
    revert_expires_at  TIMESTAMPTZ,
    reverted_at        TIMESTAMPTZ,
    -- A newer request replaces an open one
    cancelled_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_email_change_confirm_hash UNIQUE (confirm_token_hash),
    CONSTRAINT uk_email_change_revert_hash UNIQUE (revert_token_hash),
    CONSTRAINT ck_email_change_confirm_hash_hex CHECK (confirm_token_hash IS NULL OR confirm_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_email_change_revert_hash_hex CHECK (revert_token_hash IS NULL OR revert_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_email_change_different CHECK (old_email <> new_email)
);

-- Flood limits and "cancel the open request" look up a user's requests by time
CREATE INDEX ix_email_change_requests_user_created ON email_change_requests (user_id, created_at);
