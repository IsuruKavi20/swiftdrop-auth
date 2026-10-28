package com.swiftdrop.auth.session;

import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.token.TokenResponse;

import java.time.Duration;

/** What a login or refresh hands out: a short access token and the next refresh token. */
public record SessionTokens(IssuedToken accessToken, String refreshToken, Duration refreshExpiresIn) {

    public TokenResponse toResponse() {
        return TokenResponse.bearer(accessToken.value(), accessToken.expiresIn().toSeconds(),
                refreshToken, refreshExpiresIn.toSeconds());
    }

    @Override
    public String toString() {
        return "SessionTokens[redacted, refreshExpiresIn=" + refreshExpiresIn + "]";
    }
}
