package com.swiftdrop.auth.user;

import java.time.Instant;
import java.util.UUID;

/** A user's identity profile as the API shows it, plus its ETag (a fingerprint of exactly these values). */
public record ProfileView(UUID id, String name, String givenName, String familyName, String pictureUrl,
                          String locale, String email, boolean emailVerified, Instant updatedAt, String etag) {

    /** Personal data: never print it. */
    @Override
    public String toString() {
        return "ProfileView[redacted]";
    }
}
