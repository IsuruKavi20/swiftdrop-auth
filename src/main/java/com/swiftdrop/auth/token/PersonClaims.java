package com.swiftdrop.auth.token;

/**
 * Who the person behind a user token is, as OpenID Connect standard claims ({@code email}, {@code email_verified},
 * {@code name}). Small and non-secret on purpose: never picture, phone or address (USER-DATA-AND-IDENTITY.md
 * section 8). {@code name} is null for accounts without a profile name.
 */
public record PersonClaims(String email, boolean emailVerified, String name) {

    /** Personal data: never print it, even by accident in a log line. */
    @Override
    public String toString() {
        return "PersonClaims[redacted]";
    }
}
