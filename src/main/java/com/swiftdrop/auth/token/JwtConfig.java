package com.swiftdrop.auth.token;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Where the signing key comes from: a PEM file (production: must exist), created on first start in
 * development, or a throw-away in-memory key in tests. Production refuses the last two.
 */
@Configuration
class JwtConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);

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

    @Bean
    JwtEncoder jwtEncoder(RSAKey jwtSigningKey) {
        return encoder(jwtSigningKey);
    }

    static JwtEncoder encoder(RSAKey signingKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));
    }
}
