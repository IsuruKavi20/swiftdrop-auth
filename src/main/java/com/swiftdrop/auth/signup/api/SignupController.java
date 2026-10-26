package com.swiftdrop.auth.signup.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.ResponseTimeFloor;
import com.swiftdrop.auth.signup.SignupService;
import com.swiftdrop.auth.signup.api.dto.SignupAcceptedResponse;
import com.swiftdrop.auth.signup.api.dto.SignupRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** HTTP only: DTO in, use case call, DTO out. No business rules here. */
@RestController
@RequestMapping(ApiPaths.AUTH)
public class SignupController {

    private final SignupService signupService;
    private final ResponseTimeFloor responseTimeFloor;

    public SignupController(SignupService signupService, ResponseTimeFloor responseTimeFloor) {
        this.signupService = signupService;
        this.responseTimeFloor = responseTimeFloor;
    }

    /** Always 202 with the same body: the response never reveals whether the email was already registered. */
    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.ACCEPTED)
    public SignupAcceptedResponse signUp(@Valid @RequestBody SignupRequest request) {
        // Same minimum response time whether or not the email exists
        responseTimeFloor.atLeast(() -> signupService.signUp(request.email(), request.password()));
        return SignupAcceptedResponse.ACCEPTED;
    }
}
