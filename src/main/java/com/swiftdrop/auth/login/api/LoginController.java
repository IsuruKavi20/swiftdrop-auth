package com.swiftdrop.auth.login.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.login.LoginService;
import com.swiftdrop.auth.login.api.dto.LoginRequest;
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

/** HTTP only: credentials in, a bearer access token and a refresh token out. */
@RestController
@RequestMapping(ApiPaths.AUTH)
public class LoginController {

    private final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse tokens = loginService.login(request.email(), request.password()).toResponse();
        // RFC 6749 5.1: token responses must never be cached
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(tokens);
    }
}
