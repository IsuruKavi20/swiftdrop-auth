package com.swiftdrop.auth.session;

import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.token.TokenResponse;

import java.time.Duration;

/** What a login or refresh hands out: a short access token, the next refresh token, and the OIDC ID token. */
public record SessionTokens(IssuedToken accessToken, String refreshToken, Duration refreshExpiresIn, String idToken) {

    /** Without an ID token (tests and callers that don't need one). */
    public SessionTokens(IssuedToken accessToken, String refreshToken, Duration refreshExpiresIn) {
        this(accessToken, refreshToken, refreshExpiresIn, null);
    }

    public TokenResponse toResponse() {
        return TokenResponse.bearer(accessToken.value(), accessToken.expiresIn().toSeconds(),
                refreshToken, refreshExpiresIn.toSeconds(), idToken);
    }

    @Override
    public String toString() {
        return "SessionTokens[redacted, refreshExpiresIn=" + refreshExpiresIn + "]";
    }
}
