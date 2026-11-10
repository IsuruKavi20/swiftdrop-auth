package com.swiftdrop.auth.introspection.api;

import com.swiftdrop.auth.common.web.BasicCredentials;
import com.swiftdrop.auth.directory.DirectoryProperties;
import com.swiftdrop.auth.directory.ServiceClients;
import com.swiftdrop.auth.introspection.RevokedAccessTokens;
import com.swiftdrop.auth.introspection.TokenIntrospection;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

/**
 * Identity step 10: POST /oauth2/introspect (RFC 7662, our service clients with token:introspect only) and
 * POST /oauth2/revoke (RFC 7009, whoever holds the token). Form-encoded, like the token endpoint.
 */
@RestController
public class IntrospectionController {

    public static final String INTROSPECT = "/oauth2/introspect";
    public static final String REVOKE = "/oauth2/revoke";

    private final TokenIntrospection introspection;
    private final RevokedAccessTokens revocation;
    private final ServiceClients serviceClients;

    IntrospectionController(TokenIntrospection introspection, RevokedAccessTokens revocation,
                            ServiceClients serviceClients) {
        this.introspection = introspection;
        this.revocation = revocation;
        this.serviceClients = serviceClients;
    }

    @PostMapping(value = INTROSPECT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam(value = "token", required = false) String token) {
        Optional<DirectoryProperties.Client> caller = BasicCredentials.from(authorization)
                .flatMap(credentials -> serviceClients.authenticate(credentials.clientId(), credentials.secret()));
        if (caller.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"swiftdrop\"")
                    .cacheControl(CacheControl.noStore()).body(Map.of("error", "invalid_client"));
        }
        if (!caller.get().permissions().contains(DirectoryProperties.TOKEN_INTROSPECT)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "unauthorized_client"));
        }
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "invalid_request"));
        }
        // RFC 7662 4: the answer must not be cached by anyone in between
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(introspection.introspect(token));
    }

    /** Always 200, even for an unknown or broken token (RFC 7009 2.2): nobody learns whether a token was real. */
    @PostMapping(value = REVOKE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(@RequestParam(value = "token", required = false) String token,
                                       @RequestParam(value = "token_type_hint", required = false) String hint) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        // An access token is ours only if it verifies; anything else is tried as a refresh token
        introspection.decode(token).ifPresentOrElse(revocation::revokeAccessToken,
                () -> revocation.revokeRefreshToken(token));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).build();
    }
}
