package com.swiftdrop.auth.token.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.DevToolsSafetyCheck;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.token.TokenResponse;
import com.swiftdrop.auth.token.api.dto.TestTokenRequest;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RolePermissions;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * DEVELOPMENT ONLY: real, dev-signed access tokens for any role, so teammates can build and test their
 * services before roles and logins exist for them. Five locks keep it out of production:
 * (1) this class only exists with the dev profile and without prod, (2) it also needs the explicit flag,
 * (3) DevToolsSafetyCheck stops a prod start with the flag on, (4) tokens are signed with the dev key and
 * dev issuer, so production services reject them, (5) every token says test_token=true and is logged.
 */
@RestController
@Profile("dev & !prod")
@ConditionalOnBooleanProperty("swiftdrop.dev.test-tokens.enabled")
public class DevTestTokenController {

    public static final String PATH = ApiPaths.V1 + "/dev/test-tokens";
    private static final Logger log = LoggerFactory.getLogger(DevTestTokenController.class);

    private final AccessTokenIssuer issuer;
    private final RolePermissions rolePermissions;

    // Depending on the safety check guarantees it has run (and passed) before this controller can exist
    public DevTestTokenController(AccessTokenIssuer issuer, RolePermissions rolePermissions,
                                  DevToolsSafetyCheck safetyCheck) {
        this.issuer = issuer;
        this.rolePermissions = rolePermissions;
    }

    @PostMapping(value = PATH, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> testToken(@Valid @RequestBody TestTokenRequest request) {
        UUID userId = request.userId() != null ? request.userId() : UUID.randomUUID();
        List<RoleName> roleNames = request.roles().stream().distinct().toList();
        List<String> roles = roleNames.stream().map(Enum::name).toList();
        // Same permissions a real user with these roles would get, read from the database
        IssuedToken token = issuer.issueTestToken(userId, roles, rolePermissions.permissionsOf(roleNames));
        // Visible in the logs on purpose (never the token itself)
        log.warn("DEV TEST TOKEN issued userId={} roles={}", userId, roles);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(TokenResponse.bearer(token.value(), token.expiresIn().toSeconds()));
    }
}
