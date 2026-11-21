package com.swiftdrop.auth.account.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of POST /auth/password-reset ("forgot password"). */
public record PasswordResetRequestBody(@NotBlank @Size(max = 320) String email) {

    @Override
    public String toString() {
        return "PasswordResetRequestBody[email=redacted]";
    }
}
