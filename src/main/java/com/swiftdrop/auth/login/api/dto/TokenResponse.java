package com.swiftdrop.auth.login.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** The standard OAuth 2.0 token response shape (RFC 6749 section 5.1), so any client library understands it. */
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresInSeconds) {

    public static TokenResponse bearer(String accessToken, long expiresInSeconds) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds);
    }

    @Override
    public String toString() {
        return "TokenResponse[accessToken=redacted, expiresIn=" + expiresInSeconds + "]";
    }
}
