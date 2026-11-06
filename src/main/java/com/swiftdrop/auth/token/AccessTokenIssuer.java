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
 * {@code typ: at+jwt}, RS256, key ID; claims iss, sub, aud, client_id, iat, exp, jti, roles and entitlements.
 * A JWT is signed, not encrypted, so anyone holding it can read it: the only personal data is the small OIDC set
 * in {@link PersonClaims} (email, email_verified, name) on user tokens; never picture, phone or address.
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
     * A user's token with the OIDC identity claims {@code email}, {@code email_verified} and {@code name}, so
     * SwiftDrop can greet and prefill without asking again. Values can be up to one token lifetime (15 min) old:
     * fine for display, not for sending messages (use the Directory API for fresh data).
     *
     * @param roles        e.g. ["COURIER"]
     * @param entitlements the permissions those roles grant (RFC 9068 / RFC 7643 claim name), e.g. ["delivery:read-own"]
     */
    public IssuedToken issue(UUID userId, PersonClaims person, List<String> roles, List<String> entitlements) {
        return sign(userId.toString(), settings.clientId(), null, person, roles, entitlements, false);
    }

    /** Development only (see DevTestTokenController): same token, plus "test_token": true. */
    public IssuedToken issueTestToken(UUID userId, List<String> roles, List<String> entitlements) {
        return sign(userId.toString(), settings.clientId(), null, null, roles, entitlements, true);
    }

    /**
     * Client credentials (a merchant's software, no user): RFC 9068 puts the client in both {@code sub} and
     * {@code client_id}; {@code merchant_id} tells services which merchant it acts for.
     */
    public IssuedToken issueForClient(String clientId, UUID merchantId, List<String> roles, List<String> entitlements) {
        return sign(clientId, clientId, merchantId, null, roles, entitlements, false);
    }

    private IssuedToken sign(String subject, String clientId, UUID merchantId, PersonClaims person,
                             List<String> roles, List<String> entitlements, boolean testToken) {
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
        if (person != null) {
            claims.claim("email", person.email()).claim("email_verified", person.emailVerified());
            if (person.name() != null) {
                claims.claim("name", person.name());
            }
        }
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
