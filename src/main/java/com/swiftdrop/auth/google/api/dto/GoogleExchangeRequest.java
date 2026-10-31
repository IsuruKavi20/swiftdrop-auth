package com.swiftdrop.auth.google.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The one-time code from {@code /auth/callback#code=...} plus the verifier whose S256 hash the browser sent
 * when it started the login (proves this is the same browser).
 */
public record GoogleExchangeRequest(@NotBlank @Size(max = 64) String code, @NotBlank @Size(max = 64) String verifier) {

    @Override
    public String toString() {
        return "GoogleExchangeRequest[redacted]";
    }
}
