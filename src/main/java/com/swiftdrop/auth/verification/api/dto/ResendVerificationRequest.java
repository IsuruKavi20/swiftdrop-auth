package com.swiftdrop.auth.verification.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResendVerificationRequest(@NotBlank @Size(max = 320) String email) {

    @Override
    public String toString() {
        return "ResendVerificationRequest[email=redacted]";
    }
}
