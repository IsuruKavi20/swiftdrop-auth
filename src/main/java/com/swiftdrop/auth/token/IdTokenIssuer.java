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
 * OpenID Connect ID tokens (identity step 4b): tell the FRONTEND who logged in (profile claims). Three differences
 * make sure one can never be used as an access token: {@code typ: JWT} (access tokens are {@code at+jwt}), audience
 * = the frontend client (access tokens: the API), and no roles or permissions.
 */
@Component
public class IdTokenIssuer {

    private static final String ID_TOKEN_TYPE = "JWT";

    private final JwtEncoder encoder;
    private final JwtProperties settings;
    private final Clock clock;

    IdTokenIssuer(JwtEncoder encoder, JwtProperties settings, Clock clock) {
        this.encoder = encoder;
        this.settings = settings;
        this.clock = clock;
    }

    public String issue(UUID userId, IdentityClaims person) {
        Instant now = clock.instant();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type(ID_TOKEN_TYPE).keyId(settings.keyId()).build();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(settings.issuer().toString())
                .subject(userId.toString())
                .audience(List.of(settings.clientId()))
                .issuedAt(now)
                .expiresAt(now.plus(settings.accessTokenTtl()))
                .claim("email", person.email())
                .claim("email_verified", person.emailVerified());
        putIfPresent(claims, "name", person.name());
        putIfPresent(claims, "given_name", person.givenName());
        putIfPresent(claims, "family_name", person.familyName());
        putIfPresent(claims, "picture", person.picture());
        putIfPresent(claims, "locale", person.locale());
        if (person.updatedAt() != null) {
            claims.claim("updated_at", person.updatedAt().getEpochSecond());
        }
        return encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    private static void putIfPresent(JwtClaimsSet.Builder claims, String name, String value) {
        if (value != null) {
            claims.claim(name, value);
        }
    }
}
