package com.swiftdrop.auth.token;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Identity step 4b: the OpenID Connect ID token (for the frontend; never usable as an access token). */
class IdTokenIssuerTest {

    private static final Instant NOW = Instant.now();
    private static final JwtProperties SETTINGS = new JwtProperties(
            URI.create("https://auth.swiftdrop.dev"), "swiftdrop-api", "swiftdrop-web",
            Duration.ofMinutes(15), "auth-test", null, false, true, List.of());
    private static final IdentityClaims NIMAL = new IdentityClaims("nimal@example.com", true, "Nimal Perera",
            "Nimal", "Perera", "https://lh3.googleusercontent.com/a/p", "si-LK", Instant.parse("2026-11-06T10:00:00Z"));

    private final RSAKey signingKey = SigningKeys.generate("auth-test");
    private final IdTokenIssuer issuer = new IdTokenIssuer(JwtConfig.encoder(signingKey), SETTINGS,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void isAStandardIdTokenForTheFrontend() throws Exception {
        UUID userId = UUID.randomUUID();
        Jwt idToken = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey()).build()
                .decode(issuer.issue(userId, NIMAL));

        assertThat(idToken.getHeaders()).containsEntry("typ", "JWT").containsEntry("alg", "RS256")
                .containsEntry("kid", "auth-test");
        assertThat(idToken.getIssuer()).hasToString("https://auth.swiftdrop.dev");
        assertThat(idToken.getSubject()).isEqualTo(userId.toString());
        assertThat(idToken.getAudience()).containsExactly("swiftdrop-web");   // the frontend, not the API
        assertThat(idToken.getClaimAsString("name")).isEqualTo("Nimal Perera");
        assertThat(idToken.getClaimAsString("given_name")).isEqualTo("Nimal");
        assertThat(idToken.getClaimAsString("picture")).isEqualTo("https://lh3.googleusercontent.com/a/p");
        assertThat(idToken.getClaimAsString("locale")).isEqualTo("si-LK");
        assertThat(idToken.getClaimAsBoolean("email_verified")).isTrue();
        assertThat(((Number) idToken.getClaim("updated_at")).longValue())
                .isEqualTo(Instant.parse("2026-11-06T10:00:00Z").getEpochSecond());
        assertThat(idToken.getClaims()).doesNotContainKeys("roles", "entitlements", "client_id");
    }

    @Test
    void absentProfileFieldsAreLeftOut() throws Exception {
        IdentityClaims bare = new IdentityClaims("old@example.com", true, null, null, null, null, null, null);

        Jwt idToken = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey()).build()
                .decode(issuer.issue(UUID.randomUUID(), bare));

        assertThat(idToken.getClaims()).doesNotContainKeys("name", "picture", "locale", "updated_at")
                .containsKey("email");
    }

    @Test
    void anIdTokenIsNeverAcceptedAsAnAccessToken() throws Exception {
        // Exactly how our API (and SwiftDrop) verify ACCESS tokens: typ at+jwt, audience swiftdrop-api
        NimbusJwtDecoder accessTokenVerifier = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey())
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"))))
                .build();
        accessTokenVerifier.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer("https://auth.swiftdrop.dev").audience("swiftdrop-api").clientId("swiftdrop-web").build());

        String idToken = issuer.issue(UUID.randomUUID(), NIMAL);

        assertThatThrownBy(() -> accessTokenVerifier.decode(idToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void identityClaimsNeverPrintTheirValues() {
        assertThat(NIMAL.toString()).doesNotContain("nimal", "Nimal", "Perera");
    }
}
