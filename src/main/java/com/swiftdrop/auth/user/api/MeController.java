package com.swiftdrop.auth.user.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.user.api.dto.MeResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * The first protected endpoint: only reachable with a valid access token. It answers from the token itself
 * (already verified by the security filter chain), without a database call.
 */
@RestController
public class MeController {

    @GetMapping(ApiPaths.AUTH + "/me")
    public MeResponse me(@AuthenticationPrincipal Jwt token) {
        try {
            List<String> roles = token.getClaimAsStringList("roles");
            return new MeResponse(UUID.fromString(token.getSubject()), roles == null ? List.of() : roles);
        } catch (IllegalArgumentException malformedClaims) {
            // Defence in depth: a token with an unusable sub/roles is treated as invalid (401), never a 500
            throw new BadCredentialsException("Malformed token claims");
        }
    }
}
