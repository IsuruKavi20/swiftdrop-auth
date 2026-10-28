package com.swiftdrop.auth.session;

/** Why a session (refresh-token family) ended. Stored in refresh_tokens.revoke_reason. */
public enum RevokeReason {
    LOGOUT,
    REUSE_DETECTED,
    ROLE_CHANGED,
    ACCOUNT_DISABLED
}
