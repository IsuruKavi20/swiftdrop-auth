package com.swiftdrop.auth.token;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Rotation: a new key signs, the old public key stays published so tokens it signed keep working. */
class KeyRotationTest {

    private static final JwtProperties SETTINGS = new JwtProperties(
            URI.create("https://auth.swiftdrop.dev"), "swiftdrop-api", "swiftdrop-web",
            Duration.ofMinutes(15), "auth-2026-11", null, false, true, List.of());

    private final RSAKey oldKey = SigningKeys.generate("auth-2026-10");
    private final RSAKey newKey = SigningKeys.generate("auth-2026-11");

    @Test
    void publishedSetHasActiveAndPreviousKeysButOnlyPublicParts() {
        JWKSet published = JwtConfig.publicKeySet(newKey, List.of(oldKey.toPublicJWK()));

        assertThat(published.getKeys()).extracting(JWK::getKeyID).containsExactly("auth-2026-11", "auth-2026-10");
        assertThat(published.getKeys()).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
        assertThat(published.toString()).doesNotContain("\"d\"").doesNotContain("\"p\"").doesNotContain("\"q\"");
    }

    @Test
    void newTokensAreSignedWithTheActiveKey() {
        AccessTokenIssuer issuer = new AccessTokenIssuer(JwtConfig.encoder(newKey), SETTINGS, Clock.systemUTC());
        JwtDecoder decoder = JwtConfig.decoder(JwtConfig.publicKeySet(newKey, List.of(oldKey.toPublicJWK())), SETTINGS);

        assertThat(decoder.decode(issuer.issue(UUID.randomUUID(), List.of("CUSTOMER"), List.of()).value()).getHeaders())
                .containsEntry("kid", "auth-2026-11");
    }

    @Test
    void tokenSignedBeforeTheRotationStillVerifiesWhileTheOldKeyIsPublished() {
        JwtProperties beforeRotationSettings = new JwtProperties(SETTINGS.issuer(), SETTINGS.audience(),
                SETTINGS.clientId(), SETTINGS.accessTokenTtl(), "auth-2026-10", null, false, true, List.of());
        AccessTokenIssuer beforeRotation = new AccessTokenIssuer(JwtConfig.encoder(oldKey), beforeRotationSettings,
                Clock.systemUTC());
        String oldToken = beforeRotation.issue(UUID.randomUUID(), List.of("CUSTOMER"), List.of()).value();

        JwtDecoder duringOverlap = JwtConfig.decoder(JwtConfig.publicKeySet(newKey, List.of(oldKey.toPublicJWK())), SETTINGS);
        JwtDecoder afterOverlap = JwtConfig.decoder(JwtConfig.publicKeySet(newKey, List.of()), SETTINGS);

        assertThat(duringOverlap.decode(oldToken).getSubject()).isNotBlank();
        assertThatThrownBy(() -> afterOverlap.decode(oldToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void encoderRefusesToSignWithAKeyIdItDoesNotHold() {
        // Header says kid auth-2026-11, but the encoder only holds auth-2026-10: nothing gets signed
        AccessTokenIssuer mismatched = new AccessTokenIssuer(JwtConfig.encoder(oldKey), SETTINGS, Clock.systemUTC());

        assertThatThrownBy(() -> mismatched.issue(UUID.randomUUID(), List.of("CUSTOMER"), List.of()))
                .isInstanceOf(org.springframework.security.oauth2.jwt.JwtEncodingException.class);
    }

    @Test
    void previousKeyIdsMustBeDistinctFromTheActiveOne() {
        assertThatThrownBy(() -> new JwtProperties(URI.create("https://auth.swiftdrop.dev"), "swiftdrop-api",
                "swiftdrop-web", Duration.ofMinutes(15), "auth-2026-11", null, false, true,
                List.of(new JwtProperties.PreviousKey("auth-2026-11", java.nio.file.Path.of("old.pem")))))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
