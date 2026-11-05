package com.swiftdrop.auth.google;

import com.swiftdrop.auth.user.IdentityProfile;

/**
 * What we take from Google's verified ID token: the permanent id ({@code sub}), the email, whether Google
 * verified it, {@code hd} (the Google Workspace domain, absent for personal accounts) and the profile claims
 * (name, given/family name, picture, locale), already cleaned by {@link IdentityProfile#fromProvider}.
 */
public record GoogleIdentity(String sub, String email, boolean emailVerified, String hostedDomain,
                             IdentityProfile profile) {

    public GoogleIdentity {
        profile = profile == null ? IdentityProfile.empty() : profile;
    }

    /** Without profile claims (Google sends them only with the {@code profile} scope, and they may be missing). */
    public GoogleIdentity(String sub, String email, boolean emailVerified, String hostedDomain) {
        this(sub, email, emailVerified, hostedDomain, null);
    }

    static GoogleIdentity of(String sub, String email, boolean emailVerified) {
        return new GoogleIdentity(sub, email, emailVerified, null);
    }
}
