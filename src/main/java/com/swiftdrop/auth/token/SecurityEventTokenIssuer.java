package com.swiftdrop.auth.token;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.List;
import java.util.Map;

/**
 * Signs identity events as Security Event Tokens (RFC 8417; identity step 6b) with our usual keys, so receivers verify
 * them with our JWKS and no shared secret exists. A SET can never pass as another token: {@code typ: secevent+jwt},
 * no {@code exp} (it states a fact, it is not a credential) and the person in {@code sub_id} (RFC 9493), not {@code sub}.
 */
@Component
public class SecurityEventTokenIssuer {

    private static final String SET_TYPE = "secevent+jwt";

    private final JwtEncoder encoder;
    private final JwtProperties settings;
    private final Clock clock;

    SecurityEventTokenIssuer(JwtEncoder encoder, JwtProperties settings, Clock clock) {
        this.encoder = encoder;
        this.settings = settings;
        this.clock = clock;
    }

    /** @param audience the receiver this SET is for (e.g. swiftdrop-backend) */
    public String issue(SecurityEvent event, String audience) {
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type(SET_TYPE).keyId(settings.keyId()).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(settings.issuer().toString())
                .audience(List.of(audience))
                .id(event.id().toString())
                .issuedAt(clock.instant())
                .claim("sub_id", Map.of("format", "opaque", "id", event.userId().toString()))
                .claim("events", Map.of(event.eventType(), event.data()))
                .claim("toe", event.occurredAt().getEpochSecond())
                .claim("swiftdrop_version", event.version())
                .build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
