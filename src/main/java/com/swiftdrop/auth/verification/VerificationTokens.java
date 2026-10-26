package com.swiftdrop.auth.verification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * One-time tokens for email links: 256 random bits from a CSPRNG, base64url-encoded (43 characters).
 * Only the SHA-256 hash is stored. A fast hash is right here: unlike a human password, a 256-bit random
 * token cannot be guessed, so slowing down hashing would add nothing.
 */
final class VerificationTokens {

    private static final int TOKEN_BYTES = 32;
    private static final Pattern WELL_FORMED = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private VerificationTokens() {
    }

    static String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return BASE64_URL.encodeToString(bytes);
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    static boolean isWellFormed(String candidate) {
        return candidate != null && WELL_FORMED.matcher(candidate).matches();
    }
}
