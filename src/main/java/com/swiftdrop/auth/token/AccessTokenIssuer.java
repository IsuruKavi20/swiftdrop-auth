package com.swiftdrop.auth.token;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Signs access tokens following RFC 9068 (JWT profile for OAuth 2.0 access tokens): header
 * {@code typ: at+jwt}, RS256, key ID; claims iss, sub, aud, client_id, iat, exp, jti and roles.
 * No personal data: a JWT is signed, not encrypted, so anyone holding it can read it.
 */
@Component
public class AccessTokenIssuer {

    private static final String ACCESS_TOKEN_TYPE = "at+jwt";
    /** Marks tokens from the dev-only test-token endpoint, so they're recognisable everywhere. */
    public static final String TEST_TOKEN_CLAIM = "test_token";
    public static final String MERCHANT_ID_CLAIM = "merchant_id";

    private final JwtEncoder encoder;
    private final JwtProperties settings;
    private final Clock clock;

    AccessTokenIssuer(JwtEncoder encoder, JwtProperties settings, Clock clock) {
        this.encoder = encoder;
        this.settings = settings;
        this.clock = clock;
    }

    /**
     * @param roles        e.g. ["COURIER"]
     * @param entitlements the permissions those roles grant (RFC 9068 / RFC 7643 claim name), e.g. ["delivery:read-own"]
     */
    public IssuedToken issue(UUID userId, List<String> roles, List<String> entitlements) {
        return sign(userId.toString(), settings.clientId(), null, roles, entitlements, false);
    }

    /** Development only (see DevTestTokenController): same token, plus "test_token": true. */
    public IssuedToken issueTestToken(UUID userId, List<String> roles, List<String> entitlements) {
        return sign(userId.toString(), settings.clientId(), null, roles, entitlements, true);
    }

    /**
     * Client credentials (a merchant's software, no user): RFC 9068 puts the client in both {@code sub} and
     * {@code client_id}; {@code merchant_id} tells services which merchant it acts for.
     */
    public IssuedToken issueForClient(String clientId, UUID merchantId, List<String> roles, List<String> entitlements) {
        return sign(clientId, clientId, merchantId, roles, entitlements, false);
    }

    private IssuedToken sign(String subject, String clientId, UUID merchantId, List<String> roles,
                             List<String> entitlements, boolean testToken) {
        Instant now = clock.instant();
        // Spring's encoder doesn't set at+jwt by itself (spring-security#18325), so the header is explicit
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .type(ACCESS_TOKEN_TYPE)
                .keyId(settings.keyId())
                .build();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(settings.issuer().toString())
                .subject(subject)
                .audience(List.of(settings.audience()))
                .claim("client_id", clientId)
                .issuedAt(now)
                .expiresAt(now.plus(settings.accessTokenTtl()))
                .id(UUID.randomUUID().toString())
                .claim("roles", List.copyOf(roles))
                .claim("entitlements", List.copyOf(entitlements));
        if (merchantId != null) {
            claims.claim(MERCHANT_ID_CLAIM, merchantId.toString());
        }
        if (testToken) {
            claims.claim(TEST_TOKEN_CLAIM, true);
        }
        String token = encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
        return new IssuedToken(token, settings.accessTokenTtl());
    }
}
