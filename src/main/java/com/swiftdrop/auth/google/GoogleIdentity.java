package com.swiftdrop.auth.google;

/**
 * What we take from Google's verified ID token: the permanent id ({@code sub}), the email, whether Google
 * verified it, and {@code hd} (the Google Workspace domain, absent for personal accounts).
 */
public record GoogleIdentity(String sub, String email, boolean emailVerified, String hostedDomain) {

    static GoogleIdentity of(String sub, String email, boolean emailVerified) {
        return new GoogleIdentity(sub, email, emailVerified, null);
    }
}
