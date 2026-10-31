package com.swiftdrop.auth.verification.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VerifyEmailRequest(@NotBlank @Size(max = 64) String token) {

    /** The token is a credential: never print it. */
    @Override
    public String toString() {
        return "VerifyEmailRequest[token=redacted]";
    }
}
