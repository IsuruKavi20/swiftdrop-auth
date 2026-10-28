package com.swiftdrop.auth.google.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.google.HandoffCodes;
import com.swiftdrop.auth.google.api.dto.GoogleExchangeRequest;
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

/** Last step of Google login: the frontend swaps the one-time code for our normal tokens. */
@RestController
@RequestMapping(ApiPaths.AUTH)
public class GoogleExchangeController {

    private final HandoffCodes handoffCodes;

    public GoogleExchangeController(HandoffCodes handoffCodes) {
        this.handoffCodes = handoffCodes;
    }

    @PostMapping(value = "/google/exchange", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> exchange(@Valid @RequestBody GoogleExchangeRequest request) {
        TokenResponse tokens = handoffCodes.redeem(request.code(), request.verifier()).toResponse();
        // RFC 6749 5.1: token responses must never be cached
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(tokens);
    }
}
