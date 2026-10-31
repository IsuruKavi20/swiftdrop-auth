package com.swiftdrop.auth.merchant.api;

import com.swiftdrop.auth.merchant.InvalidClientException;
import com.swiftdrop.auth.merchant.MerchantClients;
import com.swiftdrop.auth.merchant.api.dto.TokenErrorResponse;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.token.TokenResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * OAuth 2.0 token endpoint for merchants' software: client credentials grant only (RFC 6749 4.4), client
 * authentication by HTTP Basic (2.3.1). Answers in the RFC 6749 shapes (5.1 / 5.2) that OAuth libraries expect.
 */
@RestController
public class TokenEndpointController {

    private static final String CLIENT_CREDENTIALS = "client_credentials";
    private static final String BASIC_PREFIX = "Basic ";

    private final MerchantClients clients;

    public TokenEndpointController(MerchantClients clients) {
        this.clients = clients;
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> token(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                   @RequestParam(value = "grant_type", required = false) String grantType) {
        String[] credentials = basicCredentials(authorization);
        if (grantType == null || grantType.isBlank()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        if (!CLIENT_CREDENTIALS.equals(grantType)) {
            return error(HttpStatus.BAD_REQUEST, "unsupported_grant_type");
        }
        IssuedToken token = clients.issueToken(credentials[0], credentials[1]);
        // RFC 6749 5.1: token responses must never be cached. No refresh token for this grant (4.4.3).
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(TokenResponse.bearer(token.value(), token.expiresIn().toSeconds()));
    }

    @ExceptionHandler(InvalidClientException.class)
    ResponseEntity<TokenErrorResponse> invalidClient() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"swiftdrop\"")
                .cacheControl(CacheControl.noStore())
                .body(new TokenErrorResponse("invalid_client"));
    }

    private static ResponseEntity<TokenErrorResponse> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(new TokenErrorResponse(code));
    }

    // "Basic base64(urlencode(id):urlencode(secret))"; anything unreadable is simply an invalid client
    private static String[] basicCredentials(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            throw new InvalidClientException();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(BASIC_PREFIX.length()).trim()),
                    StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon <= 0) {
                throw new InvalidClientException();
            }
            return new String[] {URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                    URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8)};
        } catch (IllegalArgumentException unreadable) {
            throw new InvalidClientException();
        }
    }
}
