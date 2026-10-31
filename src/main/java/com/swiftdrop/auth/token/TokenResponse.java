package com.swiftdrop.auth.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The standard OAuth 2.0 token response shape (RFC 6749 section 5.1), so any client library understands it.
 * Shared by login, refresh and the dev test-token endpoint, so clients handle all of them the same way.
 * The refresh fields are left out when there is no refresh token (dev test tokens).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresInSeconds,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("refresh_expires_in") Long refreshExpiresInSeconds) {

    public static TokenResponse bearer(String accessToken, long expiresInSeconds) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds, null, null);
    }

    public static TokenResponse bearer(String accessToken, long expiresInSeconds, String refreshToken,
                                       long refreshExpiresInSeconds) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds, refreshToken, refreshExpiresInSeconds);
    }

    @Override
    public String toString() {
        return "TokenResponse[tokens=redacted, expiresIn=" + expiresInSeconds + "]";
    }
}
