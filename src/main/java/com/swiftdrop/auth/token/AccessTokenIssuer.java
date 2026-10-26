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

    private final JwtEncoder encoder;
    private final JwtProperties settings;
    private final Clock clock;

    AccessTokenIssuer(JwtEncoder encoder, JwtProperties settings, Clock clock) {
        this.encoder = encoder;
        this.settings = settings;
        this.clock = clock;
    }

    public IssuedToken issue(UUID userId, List<String> roles) {
        Instant now = clock.instant();
        // Spring's encoder doesn't set at+jwt by itself (spring-security#18325), so the header is explicit
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .type(ACCESS_TOKEN_TYPE)
                .keyId(settings.keyId())
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(settings.issuer().toString())
                .subject(userId.toString())
                .audience(List.of(settings.audience()))
                .claim("client_id", settings.clientId())
                .issuedAt(now)
                .expiresAt(now.plus(settings.accessTokenTtl()))
                .id(UUID.randomUUID().toString())
                .claim("roles", List.copyOf(roles))
                .build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedToken(token, settings.accessTokenTtl());
    }
}
