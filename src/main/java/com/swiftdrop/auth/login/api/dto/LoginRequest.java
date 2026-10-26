package com.swiftdrop.auth.login.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Size(max = 320) String email,
        @NotNull @Size(max = 1024) String password) {

    /** Credentials must never reach a log. */
    @Override
    public String toString() {
        return "LoginRequest[email=redacted, password=redacted]";
    }
}
