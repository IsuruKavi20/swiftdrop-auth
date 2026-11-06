package com.swiftdrop.auth.token;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Identity step 6b: one identity event as a signed Security Event Token (RFC 8417). */
class SecurityEventTokenIssuerTest {

    private static final Instant NOW = Instant.parse("2026-11-07T10:00:05Z");
    private static final JwtProperties SETTINGS = new JwtProperties(
            URI.create("https://auth.swiftdrop.dev"), "swiftdrop-api", "swiftdrop-web",
            Duration.ofMinutes(15), "auth-test", null, false, true, List.of());
    private static final String DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

    private final RSAKey signingKey = SigningKeys.generate("auth-test");
    private final SecurityEventTokenIssuer issuer = new SecurityEventTokenIssuer(JwtConfig.encoder(signingKey),
            SETTINGS, Clock.fixed(NOW, ZoneOffset.UTC));

    private final UUID eventId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private final SecurityEvent event = new SecurityEvent(eventId, userId, 7, DISABLED, Map.of("reason", "ADMIN"),
            Instant.parse("2026-11-07T10:00:00Z"));

    @Test
    void isAStandardSetSignedWithOurKey() throws Exception {
        SignedJWT set = SignedJWT.parse(issuer.issue(event, "swiftdrop-backend"));

        assertThat(set.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(signingKey.toRSAPublicKey()))).isTrue();
        assertThat(set.getHeader().getType()).hasToString("secevent+jwt");
        assertThat(set.getHeader().getKeyID()).isEqualTo("auth-test");
        var claims = set.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://auth.swiftdrop.dev");
        assertThat(claims.getAudience()).containsExactly("swiftdrop-backend");
        assertThat(claims.getJWTID()).isEqualTo(eventId.toString());              // the diary line's id
        assertThat(claims.getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(claims.getJSONObjectClaim("sub_id")).containsEntry("format", "opaque")
                .containsEntry("id", userId.toString());
        assertThat(claims.getJSONObjectClaim("events")).containsOnlyKeys(DISABLED);
        assertThat(claims.getLongClaim("toe")).isEqualTo(Instant.parse("2026-11-07T10:00:00Z").getEpochSecond());
        assertThat(claims.getLongClaim("swiftdrop_version")).isEqualTo(7L);
    }

    @Test
    void hasNoExpiryAndNoSubjectClaim() throws Exception {
        var claims = SignedJWT.parse(issuer.issue(event, "swiftdrop-backend")).getJWTClaimsSet();

        // RFC 8417: a SET states a fact; it is not a credential, so no "exp". The person is in "sub_id"
        // (RFC 9493), not "sub", so no library mistakes the SET for a token about a logged-in user.
        assertThat(claims.getExpirationTime()).isNull();
        assertThat(claims.getSubject()).isNull();
    }

    @Test
    void aSetIsNeverAcceptedAsAnAccessToken() throws Exception {
        NimbusJwtDecoder accessTokenVerifier = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey())
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"))))
                .build();
        accessTokenVerifier.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer("https://auth.swiftdrop.dev").audience("swiftdrop-api").clientId("swiftdrop-web").build());

        String set = issuer.issue(event, "swiftdrop-api");   // even with the API's own audience

        assertThatThrownBy(() -> accessTokenVerifier.decode(set)).isInstanceOf(JwtException.class);
    }

    @Test
    void aSetIsNeverAcceptedAsAnIdToken() throws Exception {
        NimbusJwtDecoder idTokenReader = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey())
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT)))
                .build();

        String set = issuer.issue(event, "swiftdrop-web");

        assertThatThrownBy(() -> idTokenReader.decode(set)).isInstanceOf(JwtException.class);
    }

    @Test
    void eventsNeverPrintTheirData() {
        assertThat(event.toString()).doesNotContain("ADMIN");
    }
}
