package com.swiftdrop.auth.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Opaque one-time tokens (email links, refresh tokens): 256 random bits from a CSPRNG, base64url-encoded
 * (43 characters). Only the SHA-256 hash is stored. A fast hash is right here: unlike a human password,
 * a 256-bit random token cannot be guessed, so slowing down hashing would add nothing.
 */
public final class OpaqueTokens {

    private static final int TOKEN_BYTES = 32;
    private static final Pattern WELL_FORMED = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private OpaqueTokens() {
    }

    public static String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return BASE64_URL.encodeToString(bytes);
    }

    /** Random identifier of {@code bytes} random bytes, base64url without padding (16 bytes = 22 characters). */
    public static String randomBase64Url(int bytes) {
        byte[] random = new byte[bytes];
        RANDOM.nextBytes(random);
        return BASE64_URL.encodeToString(random);
    }

    public static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    /** PKCE "S256" (RFC 7636): base64url(SHA-256(verifier)), 43 characters. */
    public static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return BASE64_URL.encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    /** Constant-time comparison, so response timing reveals nothing about how much of a secret matched. */
    public static boolean matches(String expected, String actual) {
        return expected != null && actual != null
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII));
    }

    public static boolean isWellFormed(String candidate) {
        return candidate != null && WELL_FORMED.matcher(candidate).matches();
    }
}
