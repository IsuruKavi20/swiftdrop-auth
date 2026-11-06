package com.swiftdrop.auth.token.api;

import com.swiftdrop.auth.token.JwtProperties;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OpenID Connect Discovery 1.0 (identity step 4a): where our keys, token and userinfo endpoints are. A service then
 * needs only our issuer URL (Spring: {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}).
 * <p>
 * It lists only what we really offer. There is no {@code authorization_endpoint}: logins go through our own API
 * (password, Google, refresh), not the OAuth browser redirect flow; advertising one would mislead clients.
 */
@RestController
public class OidcDiscoveryController {

    public static final String PATH = "/.well-known/openid-configuration";
    private static final Duration CACHE_FOR = Duration.ofHours(1);

    private final Map<String, Object> metadata;

    OidcDiscoveryController(JwtProperties settings) {
        String issuer = settings.issuer().toString().replaceAll("/+$", "");
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("issuer", settings.issuer().toString());
        document.put("jwks_uri", issuer + JwksController.PATH);
        document.put("token_endpoint", issuer + "/oauth2/token");
        document.put("userinfo_endpoint", issuer + "/oauth2/userinfo");
        document.put("grant_types_supported", List.of("client_credentials"));
        document.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic"));
        document.put("response_types_supported", List.of("token"));
        document.put("subject_types_supported", List.of("public"));
        document.put("id_token_signing_alg_values_supported", List.of("RS256"));
        document.put("scopes_supported", List.of("openid", "profile", "email"));
        document.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "name", "given_name",
                "family_name", "picture", "locale", "updated_at", "email", "email_verified"));
        this.metadata = Map.copyOf(document);
    }

    @GetMapping(PATH)
    public ResponseEntity<Map<String, Object>> discovery() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(CACHE_FOR).cachePublic()).body(metadata);
    }
}
