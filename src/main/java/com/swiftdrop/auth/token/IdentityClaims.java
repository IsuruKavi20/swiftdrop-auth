package com.swiftdrop.auth.token;

import java.time.Instant;

/**
 * The person as OpenID Connect standard claims, for the ID token and /userinfo. Any field may be null (left out).
 * {@code updatedAt} becomes {@code updated_at} in seconds since 1970 (OIDC Core 5.1).
 */
public record IdentityClaims(String email, boolean emailVerified, String name, String givenName, String familyName,
                             String picture, String locale, Instant updatedAt) {

    /** Personal data: never print it. */
    @Override
    public String toString() {
        return "IdentityClaims[redacted]";
    }
}
