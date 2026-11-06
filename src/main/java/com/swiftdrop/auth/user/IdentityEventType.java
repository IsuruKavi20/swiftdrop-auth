package com.swiftdrop.auth.user;

/**
 * What can happen to a person (identity step 6). Standard OpenID Shared Signals names where one exists (RISC for
 * account events, CAEP for session/credential events); SwiftDrop's own names for the rest.
 */
public enum IdentityEventType {

    REGISTERED("https://schemas.swiftdrop.me/secevent/identity/user-registered"),
    PROFILE_UPDATED("https://schemas.swiftdrop.me/secevent/identity/profile-updated"),
    ROLES_CHANGED("https://schemas.swiftdrop.me/secevent/identity/roles-changed"),
    IDENTIFIER_CHANGED("https://schemas.openid.net/secevent/risc/event-type/identifier-changed"),
    ACCOUNT_DISABLED("https://schemas.openid.net/secevent/risc/event-type/account-disabled"),
    ACCOUNT_ENABLED("https://schemas.openid.net/secevent/risc/event-type/account-enabled"),
    ACCOUNT_PURGED("https://schemas.openid.net/secevent/risc/event-type/account-purged"),
    CREDENTIAL_CHANGE("https://schemas.openid.net/secevent/caep/event-type/credential-change"),
    SESSION_REVOKED("https://schemas.openid.net/secevent/caep/event-type/session-revoked");

    private final String uri;

    IdentityEventType(String uri) {
        this.uri = uri;
    }

    public String uri() {
        return uri;
    }
}
