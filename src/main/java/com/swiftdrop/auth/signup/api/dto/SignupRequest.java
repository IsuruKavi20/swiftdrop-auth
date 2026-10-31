package com.swiftdrop.auth.signup.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * The only fields signup accepts (unknown fields are rejected by strict JSON parsing).
 * The size limits here are coarse guards; the real rules live in EmailAddress and PasswordPolicy.
 */
public record SignupRequest(
        @NotBlank @Size(max = 320) String email,
        @NotNull @Size(max = 1024) String password) {

    /** A record's default toString prints every field: the password and email must never reach a log. */
    @Override
    public String toString() {
        return "SignupRequest[email=redacted, password=redacted]";
    }
}
