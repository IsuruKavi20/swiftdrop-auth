package com.swiftdrop.auth.account.api;

import com.swiftdrop.auth.account.PasswordResetMessages;
import com.swiftdrop.auth.account.PasswordResetService;
import com.swiftdrop.auth.account.api.dto.PasswordResetConfirmBody;
import com.swiftdrop.auth.account.api.dto.PasswordResetRequestBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.ResponseTimeFloor;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Forgot password (identity step 11a). No login needed: the request answers the same for every address, and the
 * one-time token from the emailed link is the credential for the confirm call.
 */
@RestController
public class PasswordResetController {

    public static final String BASE = ApiPaths.AUTH + "/password-reset";

    private final PasswordResetService resets;
    private final ResponseTimeFloor responseTimeFloor;

    PasswordResetController(PasswordResetService resets, ResponseTimeFloor responseTimeFloor) {
        this.resets = resets;
        this.responseTimeFloor = responseTimeFloor;
    }

    @PostMapping(value = BASE, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.ACCEPTED)
    public Map<String, String> request(@Valid @RequestBody PasswordResetRequestBody body) {
        // Same minimum response time whether or not the email has an account
        responseTimeFloor.atLeast(() -> resets.request(body.email()));
        return Map.of("message", PasswordResetMessages.ACCEPTED);
    }

    @PostMapping(value = BASE + "/confirm", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void confirm(@Valid @RequestBody PasswordResetConfirmBody body) {
        resets.confirm(body.token(), body.newPassword());
    }
}
