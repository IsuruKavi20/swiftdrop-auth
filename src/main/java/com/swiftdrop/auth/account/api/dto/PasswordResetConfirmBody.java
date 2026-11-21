package com.swiftdrop.auth.account.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Body of POST /auth/password-reset/confirm: the token from the link's #fragment and the new password. */
public record PasswordResetConfirmBody(
        @NotBlank @Size(max = 64) String token,
        @JsonProperty("new_password") @NotNull @Size(max = 1024) String newPassword) {

    /** Both are secrets: never in a log. */
    @Override
    public String toString() {
        return "PasswordResetConfirmBody[token=redacted, new_password=redacted]";
    }
}
