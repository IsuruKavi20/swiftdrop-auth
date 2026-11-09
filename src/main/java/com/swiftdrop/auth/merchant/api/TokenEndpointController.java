package com.swiftdrop.auth.merchant.api;

import com.swiftdrop.auth.merchant.InvalidClientException;
import com.swiftdrop.auth.merchant.MerchantClients;
import com.swiftdrop.auth.merchant.api.dto.TokenErrorResponse;
import com.swiftdrop.auth.common.web.BasicCredentials;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.directory.ServiceClients;
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


/**
 * OAuth 2.0 token endpoint for merchants' software: client credentials grant only (RFC 6749 4.4), client
 * authentication by HTTP Basic (2.3.1). Answers in the RFC 6749 shapes (5.1 / 5.2) that OAuth libraries expect.
 */
@RestController
public class TokenEndpointController {

    private static final String CLIENT_CREDENTIALS = "client_credentials";

    private final MerchantClients clients;
    private final ServiceClients serviceClients;

    public TokenEndpointController(MerchantClients clients, ServiceClients serviceClients) {
        this.clients = clients;
        this.serviceClients = serviceClients;
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
        // Our own backends (svc_..., Directory API) or a merchant's software (mc_...): same grant, same answers
        IssuedToken token = ServiceClients.isServiceClientId(credentials[0])
                ? serviceClients.issueToken(credentials[0], credentials[1]).orElseThrow(InvalidClientException::new)
                : clients.issueToken(credentials[0], credentials[1]);
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

    private static String[] basicCredentials(String authorization) {
        BasicCredentials credentials = BasicCredentials.from(authorization).orElseThrow(InvalidClientException::new);
        return new String[] {credentials.clientId(), credentials.secret()};
    }
}
