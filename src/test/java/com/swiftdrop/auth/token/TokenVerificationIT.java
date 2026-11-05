package com.swiftdrop.auth.token;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** A token from our issuer works on a protected endpoint; anything forged, expired or foreign does not. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TokenVerificationIT {

    private static final String ME = "/api/v1/auth/me";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private RSAKey jwtSigningKey;

    @Autowired
    private JwtProperties settings;

    @Test
    void jwksIsPublicCacheableAndContainsOnlyPublicKeyParts() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", containsString("application/jwk-set+json")))
                .andExpect(header().string("Cache-Control", containsString("max-age=300")))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value(jwtSigningKey.getKeyID()))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist());
    }

    @Test
    void anotherServiceCanVerifyOurTokenUsingOnlyThePublishedJwks() throws Exception {
        String jwks = mockMvc.perform(get("/.well-known/jwks.json")).andReturn().getResponse().getContentAsString();
        NimbusJwtDecoder teammateService = NimbusJwtDecoder
                .withPublicKey(JWKSet.parse(jwks).getKeys().getFirst().toRSAKey().toRSAPublicKey())
                .validateType(false).build();
        teammateService.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer("http://localhost").audience("swiftdrop-api").clientId("swiftdrop-web").build());
        UUID userId = UUID.randomUUID();

        String token = issuer.issue(userId, TestPeople.SOMEONE, List.of("COURIER"), List.of()).value();

        assertThat(teammateService.decode(token).getSubject()).isEqualTo(userId.toString());
    }

    @Test
    void validTokenOpensTheProtectedEndpoint() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = issuer.issue(userId, TestPeople.SOMEONE, List.of("COURIER"), List.of()).value();

        mockMvc.perform(get(ME).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(userId.toString()))
                .andExpect(jsonPath("$.roles[0]").value("COURIER"));
    }

    @Test
    void staleTokenOnAPublicEndpointIsIgnoredSoTheClientCanStillLogIn() throws Exception {
        // Invalid body on purpose: we only care that it's NOT a 401 caused by the bad Authorization header
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/auth/login")
                        .header("Authorization", "Bearer expired.or.garbage")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void noTokenGets401ProblemDetails() throws Exception {
        mockMvc.perform(get(ME))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    void tamperedTokenIsRejected() throws Exception {
        String token = issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "x." + parts[2];

        mockMvc.perform(get(ME).header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        Instant twoHoursAgo = Instant.now().minus(Duration.ofHours(2));
        AccessTokenIssuer past = new AccessTokenIssuer(JwtConfig.encoder(jwtSigningKey), settings,
                Clock.fixed(twoHoursAgo, ZoneOffset.UTC));

        mockMvc.perform(get(ME).header("Authorization",
                        "Bearer " + past.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void hs256ForgeryUsingThePublicKeyIsRejected() throws Exception {
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jwt")).build(),
                new JWTClaimsSet.Builder().issuer("http://localhost").subject("attacker").audience("swiftdrop-api")
                        .claim("client_id", "swiftdrop-web").claim("roles", List.of("ADMIN"))
                        .jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(600))).build());
        forged.sign(new MACSigner(jwtSigningKey.toRSAPublicKey().getEncoded()));

        mockMvc.perform(get(ME).header("Authorization", "Bearer " + forged.serialize()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.not(containsString("attacker"))));
    }

    @Test
    void tokenFromAnotherIssuerOrForAnotherAudienceIsRejected() throws Exception {
        JwtProperties foreign = new JwtProperties(java.net.URI.create("https://evil.example"), "other-api",
                "swiftdrop-web", Duration.ofMinutes(15), jwtSigningKey.getKeyID(), null, false, true, List.of());
        AccessTokenIssuer wrongIssuer = new AccessTokenIssuer(JwtConfig.encoder(jwtSigningKey), foreign,
                Clock.systemUTC());

        mockMvc.perform(get(ME).header("Authorization",
                        "Bearer " + wrongIssuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value()))
                .andExpect(status().isUnauthorized());
    }
}
