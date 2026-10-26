package com.swiftdrop.auth.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code swiftdrop.jwt.*}: who issues tokens, for which audience, how long they live, and where the
 * signing key comes from. Invalid values stop the application at startup.
 *
 * @param privateKeyLocation PEM file with the ACTIVE RSA private key (never in git)
 * @param createKeyIfMissing development only: generate the key file on first start
 * @param ephemeralKey       tests only: a new in-memory key on every start
 * @param previousKeys       public keys of earlier signing keys, still published during a rotation's overlap window
 */
@ConfigurationProperties("swiftdrop.jwt")
public record JwtProperties(URI issuer, String audience, String clientId, Duration accessTokenTtl, String keyId,
                            Path privateKeyLocation, boolean createKeyIfMissing, boolean ephemeralKey,
                            List<PreviousKey> previousKeys) {

    private static final Duration MIN_TTL = Duration.ofMinutes(1);
    private static final Duration MAX_TTL = Duration.ofMinutes(60);
    // The key ID is copied into every token header: keep it to plain characters
    private static final Pattern SAFE_KEY_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

    /** An earlier signing key: only its public half is kept, to verify tokens it signed before the rotation. */
    public record PreviousKey(String keyId, Path publicKeyLocation) {
    }

    public JwtProperties {
        if (issuer == null || !issuer.isAbsolute()) {
            throw new IllegalArgumentException("swiftdrop.jwt.issuer must be an absolute URL");
        }
        if (isBlank(audience) || isBlank(clientId)) {
            throw new IllegalArgumentException("swiftdrop.jwt.audience and client-id are required");
        }
        if (accessTokenTtl == null || accessTokenTtl.compareTo(MIN_TTL) < 0 || accessTokenTtl.compareTo(MAX_TTL) > 0) {
            throw new IllegalArgumentException("swiftdrop.jwt.access-token-ttl must be between 1 and 60 minutes");
        }
        requireSafeKeyId(keyId);
        if (!ephemeralKey && privateKeyLocation == null) {
            throw new IllegalArgumentException("swiftdrop.jwt.private-key-location is required");
        }
        previousKeys = previousKeys == null ? List.of() : List.copyOf(previousKeys);
        Set<String> keyIds = new HashSet<>(Set.of(keyId));
        for (PreviousKey previous : previousKeys) {
            requireSafeKeyId(previous.keyId());
            if (previous.publicKeyLocation() == null) {
                throw new IllegalArgumentException("swiftdrop.jwt.previous-keys[].public-key-location is required");
            }
            // Verifiers pick the key by kid: two keys with one kid would make verification ambiguous
            if (!keyIds.add(previous.keyId())) {
                throw new IllegalArgumentException("swiftdrop.jwt key ids must be unique: " + previous.keyId());
            }
        }
    }

    private static void requireSafeKeyId(String candidate) {
        if (candidate == null || !SAFE_KEY_ID.matcher(candidate).matches()) {
            throw new IllegalArgumentException("swiftdrop.jwt key ids must be 1-64 letters, digits, '.', '_' or '-'");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
