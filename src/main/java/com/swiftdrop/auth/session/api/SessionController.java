package com.swiftdrop.auth.session.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.session.api.dto.RefreshTokenRequest;
import com.swiftdrop.auth.token.TokenResponse;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Refresh (swap the refresh token for new tokens) and logout (end this session). */
@RestController
@RequestMapping(ApiPaths.AUTH)
public class SessionController {

    private final SessionService sessions;

    public SessionController(SessionService sessions) {
        this.sessions = sessions;
    }

    @PostMapping(value = "/refresh", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        TokenResponse tokens = sessions.refresh(request.refreshToken()).toResponse();
        // RFC 6749 5.1: token responses must never be cached
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(tokens);
    }

    @PostMapping(value = "/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
    // Deliberately not @Valid: logout answers 204 for anything, so it can't be used to probe tokens
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenRequest request) {
        sessions.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
