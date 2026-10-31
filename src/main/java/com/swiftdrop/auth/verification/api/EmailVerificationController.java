package com.swiftdrop.auth.verification.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.ResponseTimeFloor;
import com.swiftdrop.auth.verification.EmailVerificationService;
import com.swiftdrop.auth.verification.api.dto.ResendAcceptedResponse;
import com.swiftdrop.auth.verification.api.dto.ResendVerificationRequest;
import com.swiftdrop.auth.verification.api.dto.VerifyEmailRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Verification is POST only: email scanners "click" (GET) every link in incoming mail, so a GET must
 * never consume a token. The frontend page posts the token when the user presses "Confirm".
 */
@RestController
@RequestMapping(EmailVerificationController.BASE)
public class EmailVerificationController {

    public static final String BASE = ApiPaths.AUTH + "/email-verification";

    private final EmailVerificationService verification;
    private final ResponseTimeFloor responseTimeFloor;

    public EmailVerificationController(EmailVerificationService verification, ResponseTimeFloor responseTimeFloor) {
        this.verification = verification;
        this.responseTimeFloor = responseTimeFloor;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verify(@Valid @RequestBody VerifyEmailRequest request) {
        verification.verify(request.token());
    }

    @PostMapping(value = "/resend", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResendAcceptedResponse resend(@Valid @RequestBody ResendVerificationRequest request) {
        // Same minimum response time whether or not the email has an unverified account
        responseTimeFloor.atLeast(() -> verification.requestResend(request.email()));
        return ResendAcceptedResponse.ACCEPTED;
    }
}
