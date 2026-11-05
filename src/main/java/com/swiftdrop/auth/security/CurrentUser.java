package com.swiftdrop.auth.security;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

/** The person behind a verified access token, for endpoints about "my own" account. */
public final class CurrentUser {

    private CurrentUser() {
    }

    /**
     * A user token's {@code sub} is the user's UUID. A merchant machine token's {@code sub} is its client id: there
     * is no person behind it, so "my account" endpoints answer 403.
     */
    public static UUID idOf(Jwt token) {
        try {
            return UUID.fromString(token.getSubject());
        } catch (IllegalArgumentException notAUser) {
            throw new AccessDeniedException("Only user tokens have an account");
        }
    }
}
