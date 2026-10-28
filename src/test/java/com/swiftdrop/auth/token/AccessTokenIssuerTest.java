package com.swiftdrop.auth.token;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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

class AccessTokenIssuerTest {

    private static final Instant NOW = Instant.now();
    private static final JwtProperties SETTINGS = new JwtProperties(
            URI.create("https://auth.swiftdrop.dev"), "swiftdrop-api", "swiftdrop-web",
            Duration.ofMinutes(15), "auth-test", null, false, true, java.util.List.of());

    private final RSAKey signingKey = SigningKeys.generate("auth-test");
    private final AccessTokenIssuer issuer = new AccessTokenIssuer(
            JwtConfig.encoder(signingKey), SETTINGS, Clock.fixed(NOW, ZoneOffset.UTC));

    /** How another SwiftDrop service will verify our tokens: RS256 only, at+jwt only, our issuer and audience. */
    private NimbusJwtDecoder verifier() throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey())
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"))))
                .build();
        // Spring's built-in RFC 9068 validator: typ at+jwt, issuer, audience, client_id, exp/nbf, required claims
        decoder.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer("https://auth.swiftdrop.dev")
                .audience("swiftdrop-api")
                .clientId("swiftdrop-web")
                .build());
        return decoder;
    }

    @Test
    void issuesAnRfc9068AccessTokenThatOtherServicesCanVerify() throws Exception {
        UUID userId = UUID.randomUUID();

        IssuedToken token = issuer.issue(userId, List.of("CUSTOMER"), List.of());
        Jwt jwt = verifier().decode(token.value());

        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256").containsEntry("typ", "at+jwt")
                .containsEntry("kid", "auth-test");
        assertThat(jwt.getSubject()).isEqualTo(userId.toString());
        assertThat(jwt.getAudience()).containsExactly("swiftdrop-api");
        assertThat(jwt.getClaimAsString("client_id")).isEqualTo("swiftdrop-web");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("CUSTOMER");
        assertThat(jwt.getId()).isNotBlank();
        assertThat(token.expiresIn()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void permissionsTravelInTheEntitlementsClaim() throws Exception {
        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), List.of("DISPATCHER"),
                List.of("delivery:read-all", "parcel:assign")).value());

        assertThat(jwt.getClaimAsStringList("entitlements")).containsExactly("delivery:read-all", "parcel:assign");
    }

    @Test
    void tokenContainsNoPersonalData() throws Exception {
        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), List.of("CUSTOMER"), List.of()).value());

        assertThat(jwt.getClaims()).doesNotContainKeys("email", "name", "preferred_username");
    }

    @Test
    void testTokensAreVisiblyMarkedAndNormalTokensAreNot() throws Exception {
        Jwt test = verifier().decode(issuer.issueTestToken(UUID.randomUUID(), List.of("COURIER"), List.of()).value());
        Jwt normal = verifier().decode(issuer.issue(UUID.randomUUID(), List.of("COURIER"), List.of()).value());

        assertThat(test.getClaims()).containsEntry("test_token", true);
        assertThat(test.getClaimAsStringList("roles")).containsExactly("COURIER");
        assertThat(normal.getClaims()).doesNotContainKey("test_token");
    }

    @Test
    void everyTokenHasItsOwnId() {
        UUID userId = UUID.randomUUID();

        assertThat(issuer.issue(userId, List.of("CUSTOMER"), List.of()).value())
                .isNotEqualTo(issuer.issue(userId, List.of("CUSTOMER"), List.of()).value());
    }

    @Test
    void forgedTokenWithAnotherAlgorithmIsRejected() throws Exception {
        // Classic attack: sign with HS256 using the PUBLIC key as the "secret" and hope the verifier follows "alg"
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jwt")).build(),
                new JWTClaimsSet.Builder().issuer("https://auth.swiftdrop.dev").subject("attacker")
                        .audience("swiftdrop-api").expirationTime(java.util.Date.from(NOW.plusSeconds(600))).build());
        forged.sign(new MACSigner(signingKey.toRSAPublicKey().getEncoded()));

        assertThatThrownBy(() -> verifier().decode(forged.serialize())).isInstanceOf(JwtException.class);
    }
}
