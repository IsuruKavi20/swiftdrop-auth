-- Identity step 3b-3: undoing an email change ends every session of the account.
ALTER TABLE refresh_tokens DROP CONSTRAINT ck_refresh_tokens_reason;
ALTER TABLE refresh_tokens ADD CONSTRAINT ck_refresh_tokens_reason
    CHECK (revoke_reason IN ('LOGOUT', 'REUSE_DETECTED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED', 'ACCOUNT_RECLAIMED',
                             'EMAIL_CHANGE_UNDONE'));
