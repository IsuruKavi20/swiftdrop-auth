package com.swiftdrop.auth.token;

import java.time.Duration;

/** A signed access token and how long it stays valid. */
public record IssuedToken(String value, Duration expiresIn) {

    @Override
    public String toString() {
        return "IssuedToken[value=redacted, expiresIn=" + expiresIn + "]";
    }
}
