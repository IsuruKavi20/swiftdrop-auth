-- Identity step 9b: block/unblock and delete people from the SwiftDrop admin portal. ADMIN only.
INSERT INTO permissions (id, name) VALUES
    (15, 'user:manage-status'),
    (16, 'user:delete');
INSERT INTO role_permissions (role_id, permission_id) VALUES (5, 15), (5, 16);   -- ADMIN

-- "Log out everywhere" by an admin gets its own session-end reason
ALTER TABLE refresh_tokens DROP CONSTRAINT ck_refresh_tokens_reason;
ALTER TABLE refresh_tokens ADD CONSTRAINT ck_refresh_tokens_reason
    CHECK (revoke_reason IN ('LOGOUT', 'REUSE_DETECTED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED', 'ACCOUNT_RECLAIMED',
                             'EMAIL_CHANGE_UNDONE', 'PASSWORD_CHANGED', 'ACCOUNT_DELETED', 'ENDED_BY_ADMIN'));

-- The audit API filters by action and lists one person's history
CREATE INDEX ix_audit_log_action ON audit_log (action, seq);
