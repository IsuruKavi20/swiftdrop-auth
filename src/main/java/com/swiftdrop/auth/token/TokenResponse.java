package com.swiftdrop.auth.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The standard OAuth 2.0 token response shape (RFC 6749 section 5.1), so any client library understands it.
 * Shared by login, refresh and the dev test-token endpoint, so clients handle all of them the same way.
 * The refresh fields are left out when there is no refresh token (dev test tokens); id_token only for logins.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresInSeconds,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("refresh_expires_in") Long refreshExpiresInSeconds,
        // OpenID Connect: who logged in, for the frontend (never sent as a bearer token)
        @JsonProperty("id_token") String idToken) {

    public static TokenResponse bearer(String accessToken, long expiresInSeconds) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds, null, null, null);
    }

    public static TokenResponse bearer(String accessToken, long expiresInSeconds, String refreshToken,
                                       long refreshExpiresInSeconds, String idToken) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds, refreshToken, refreshExpiresInSeconds,
                idToken);
    }

    @Override
    public String toString() {
        return "TokenResponse[tokens=redacted, expiresIn=" + expiresInSeconds + "]";
    }
}
