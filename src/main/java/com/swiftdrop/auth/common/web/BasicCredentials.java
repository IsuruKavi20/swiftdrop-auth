package com.swiftdrop.auth.common.web;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * OAuth client authentication by HTTP Basic (RFC 6749 2.3.1): "Basic base64(urlencode(id):urlencode(secret))".
 * Anything unreadable is simply "no credentials" (the caller answers invalid_client).
 */
public record BasicCredentials(String clientId, String secret) {

    private static final String PREFIX = "Basic ";

    public static Optional<BasicCredentials> from(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            return Optional.empty();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(PREFIX.length()).trim()),
                    StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon <= 0) {
                return Optional.empty();
            }
            return Optional.of(new BasicCredentials(
                    URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                    URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }

    /** Never print the secret. */
    @Override
    public String toString() {
        return "BasicCredentials[" + clientId + "]";
    }
}
