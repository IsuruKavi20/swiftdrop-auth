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

        IssuedToken token = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of());
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
        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("DISPATCHER"),
                List.of("delivery:read-all", "parcel:assign")).value());

        assertThat(jwt.getClaimAsStringList("entitlements")).containsExactly("delivery:read-all", "parcel:assign");
    }

    @Test
    void userTokensCarryTheStandardIdentityClaims() throws Exception {
        PersonClaims nimal = new PersonClaims("nimal@example.com", true, "Nimal Perera");

        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), nimal, List.of("CUSTOMER"), List.of()).value());

        assertThat(jwt.getClaimAsString("email")).isEqualTo("nimal@example.com");
        assertThat(jwt.getClaimAsBoolean("email_verified")).isTrue();
        assertThat(jwt.getClaimAsString("name")).isEqualTo("Nimal Perera");
    }

    @Test
    void nameIsLeftOutWhenTheUserHasNone() throws Exception {
        PersonClaims noName = new PersonClaims("old@example.com", true, null);

        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), noName, List.of("CUSTOMER"), List.of()).value());

        assertThat(jwt.getClaims()).doesNotContainKey("name").containsKey("email");
    }

    @Test
    void onlyTheAgreedPersonalDataEverGoesIntoAToken() throws Exception {
        PersonClaims nimal = new PersonClaims("nimal@example.com", true, "Nimal Perera");

        Jwt jwt = verifier().decode(issuer.issue(UUID.randomUUID(), nimal, List.of("CUSTOMER"), List.of()).value());

        // Design rule (USER-DATA-AND-IDENTITY.md section 8): small, non-secret claims only. Picture stays out (size),
        // phone and address never (personal data a token doesn't need).
        assertThat(jwt.getClaims()).doesNotContainKeys("picture", "given_name", "family_name", "locale",
                "phone_number", "address", "birthdate", "preferred_username");
    }

    @Test
    void aLongestPossibleNameStillGivesASmallToken() {
        String longestSinhalaName = "ක්\u200Dෂ".repeat(50);   // 200 code points, ~600 bytes of UTF-8
        PersonClaims person = new PersonClaims("a".repeat(64) + "@" + "b".repeat(63) + ".example.com", true,
                com.swiftdrop.auth.user.PersonName.of(longestSinhalaName).value());

        String token = issuer.issue(UUID.randomUUID(), person, List.of("DISPATCHER"),
                List.of("delivery:read-all", "parcel:assign", "parcel:read-all")).value();

        // Well under the 8 KB header limit of common proxies and servers
        assertThat(token.length()).isLessThan(4096);
    }

    @Test
    void personClaimsNeverPrintTheirValues() {
        assertThat(new PersonClaims("nimal@example.com", true, "Nimal Perera").toString())
                .doesNotContain("nimal").doesNotContain("Nimal");
    }

    @Test
    void testTokensAndMachineTokensCarryNoPersonalData() throws Exception {
        Jwt test = verifier().decode(issuer.issueTestToken(UUID.randomUUID(), List.of("CUSTOMER"), List.of()).value());

        Jwt machine = verifier().decode(issuer.issueForClient("swiftdrop-web", UUID.randomUUID(),
                List.of("MERCHANT"), List.of("parcel:create")).value());

        assertThat(test.getClaims()).doesNotContainKeys("email", "email_verified", "name");
        assertThat(machine.getClaims()).doesNotContainKeys("email", "email_verified", "name");
    }

    @Test
    void onlyMerchantMachineTokensNameTheMerchantOwner() throws Exception {
        UUID merchant = UUID.randomUUID();
        UUID owner = UUID.randomUUID();
        Jwt machine = verifier().decode(issuer.issueForMerchantClient("swiftdrop-web", merchant, owner,   // verifier() accepts only this client_id
                List.of("MERCHANT"), List.of("parcel:create")).value());
        Jwt person = verifier().decode(issuer.issue(owner, TestPeople.SOMEONE, List.of("MERCHANT"), List.of()).value());
        Jwt service = verifier().decode(issuer.issueForClient("swiftdrop-web", null, List.of("SERVICE"), List.of()).value());

        assertThat(machine.getClaimAsString("merchant_owner")).isEqualTo(owner.toString());
        assertThat(machine.getClaimAsString("merchant_id")).isEqualTo(merchant.toString());
        assertThat(machine.getSubject()).isEqualTo("swiftdrop-web");   // sub stays the client (RFC 9068), not the owner
        assertThat(person.getClaims()).doesNotContainKeys("merchant_owner", "merchant_id");
        assertThat(service.getClaims()).doesNotContainKeys("merchant_owner", "merchant_id");
    }

    @Test
    void testTokensAreVisiblyMarkedAndNormalTokensAreNot() throws Exception {
        Jwt test = verifier().decode(issuer.issueTestToken(UUID.randomUUID(), List.of("COURIER"), List.of()).value());
        Jwt normal = verifier().decode(issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("COURIER"), List.of()).value());

        assertThat(test.getClaims()).containsEntry("test_token", true);
        assertThat(test.getClaimAsStringList("roles")).containsExactly("COURIER");
        assertThat(normal.getClaims()).doesNotContainKey("test_token");
    }

    @Test
    void everyTokenHasItsOwnId() {
        UUID userId = UUID.randomUUID();

        assertThat(issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value())
                .isNotEqualTo(issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value());
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
