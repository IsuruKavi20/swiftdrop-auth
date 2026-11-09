package com.swiftdrop.auth.session;

/** Why a session (refresh-token family) ended. Stored in refresh_tokens.revoke_reason. */
public enum RevokeReason {
    LOGOUT,
    REUSE_DETECTED,
    ROLE_CHANGED,
    ACCOUNT_DISABLED,
    /** An unverified password account was taken back by its real owner through Google (pre-hijack). */
    ACCOUNT_RECLAIMED,
    /** The owner used the undo link after an email change: whoever made the change is logged out (step 3b-3). */
    EMAIL_CHANGE_UNDONE,
    /** The password was changed: every old session ends, the device that changed it gets fresh tokens (3c). */
    PASSWORD_CHANGED,
    /** The owner deleted the account (identity step 3e). */
    ACCOUNT_DELETED,
    /** An administrator used "log out everywhere" (identity step 9b). */
    ENDED_BY_ADMIN
}
