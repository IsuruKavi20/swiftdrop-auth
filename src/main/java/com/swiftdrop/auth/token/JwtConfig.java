package com.swiftdrop.auth.token;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import java.util.regex.Pattern;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.util.ArrayList;
import java.util.List;

/**
 * Keys and the encoder/decoder built from them.
 * <ul>
 *   <li>The ACTIVE key (private + public) signs new tokens. Source: PEM file (production: must exist),
 *       created on first start in development, or a throw-away in-memory key in tests.</li>
 *   <li>PREVIOUS keys (public only) are still published and accepted during a rotation's overlap window.</li>
 *   <li>The decoder verifies against the public set in memory: this service never calls itself over HTTP.</li>
 * </ul>
 */
@Configuration
class JwtConfig {

    private static final Pattern MERCHANT_CLIENT_ID = Pattern.compile("^mc_[A-Za-z0-9_-]{22}$");
    private static final Pattern SERVICE_CLIENT_ID = Pattern.compile("^svc_[a-z0-9-]{3,40}$");

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);
    private static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    @Bean
    RSAKey jwtSigningKey(JwtProperties settings, Environment environment) {
        boolean production = environment.matchesProfiles("prod");
        if (production && (settings.ephemeralKey() || settings.createKeyIfMissing())) {
            throw new IllegalStateException("prod must use a provided JWT signing key "
                    + "(ephemeral-key and create-key-if-missing must be false)");
        }
        if (settings.ephemeralKey()) {
            return SigningKeys.generate(settings.keyId());
        }
        RSAKey key = SigningKeys.loadOrCreate(settings.privateKeyLocation(), settings.keyId(),
                settings.createKeyIfMissing());
        log.info("JWT signing key loaded (kid={}, {} bits)", key.getKeyID(), key.size());
        return key;
    }

    /** What /.well-known/jwks.json publishes and what our own decoder trusts: public halves only. */
    @Bean
    JWKSet jwtPublicKeys(RSAKey jwtSigningKey, JwtProperties settings) {
        List<RSAKey> previous = settings.previousKeys().stream()
                .map(key -> SigningKeys.loadPublic(key.publicKeyLocation(), key.keyId()))
                .toList();
        if (!previous.isEmpty()) {
            log.info("Rotation overlap: also accepting previous key ids {}", previous.stream().map(JWK::getKeyID).toList());
        }
        return publicKeySet(jwtSigningKey, previous);
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey jwtSigningKey) {
        return encoder(jwtSigningKey);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSet jwtPublicKeys, JwtProperties settings) {
        return decoder(jwtPublicKeys, settings);
    }

    // Only the ACTIVE key is given to the encoder, so nothing can ever be signed with a previous key
    static JwtEncoder encoder(RSAKey signingKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));
    }

    static JWKSet publicKeySet(RSAKey active, List<RSAKey> previousPublicKeys) {
        List<JWK> keys = new ArrayList<>();
        keys.add(active.toPublicJWK());
        previousPublicKeys.forEach(key -> keys.add(key.toPublicJWK()));
        return new JWKSet(keys);
    }

    /**
     * RS256 only (the token's own "alg" can't change that), typ at+jwt, then the RFC 9068 checks:
     * exact issuer, audience, client_id, expiry (60 s clock-skew leeway), required claims.
     */
    static JwtDecoder decoder(JWKSet publicKeys, JwtProperties settings) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(new ImmutableJWKSet<>(publicKeys))
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(ACCESS_TOKEN_TYPE)))
                .build();
        // client_id: our user apps (swiftdrop-web), a merchant's software (mc_...) or one of our own backends
        // (svc_..., Directory API), nothing else
        OAuth2TokenValidator<Jwt> knownClient = new JwtClaimValidator<String>("client_id",
                clientId -> settings.clientId().equals(clientId)
                        || (clientId != null && (MERCHANT_CLIENT_ID.matcher(clientId).matches()
                        || SERVICE_CLIENT_ID.matcher(clientId).matches())));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createAtJwtValidator()
                        .issuer(settings.issuer().toString())
                        .audience(settings.audience())
                        .build(),
                knownClient));
        return decoder;
    }
}
