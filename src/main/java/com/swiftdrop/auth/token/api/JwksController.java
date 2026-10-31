package com.swiftdrop.auth.token.api;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * Publishes our PUBLIC signing key(s) (RFC 7517 JWK Set) so other services verify tokens locally,
 * without calling us per request and without any shared secret.
 */
@RestController
public class JwksController {

    public static final String PATH = "/.well-known/jwks.json";
    private static final MediaType JWK_SET = MediaType.parseMediaType("application/jwk-set+json");
    // Matches Spring resource servers' default 5-minute JWK set cache
    private static final Duration CACHE_FOR = Duration.ofMinutes(5);

    private final Map<String, Object> publicKeys;

    public JwksController(JWKSet jwtPublicKeys) {
        // toPublicJWKSet() strips private members again: defence in depth, even though the set is public already
        this.publicKeys = jwtPublicKeys.toPublicJWKSet().toJSONObject();
    }

    @GetMapping(PATH)
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .contentType(JWK_SET)
                .cacheControl(CacheControl.maxAge(CACHE_FOR).cachePublic())
                .body(publicKeys);
    }
}
