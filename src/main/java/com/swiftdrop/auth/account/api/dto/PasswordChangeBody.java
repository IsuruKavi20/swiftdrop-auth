package com.swiftdrop.auth.account.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Body of POST /me/password. Coarse limits only; the password rules live in PasswordPolicy. */
public record PasswordChangeBody(
        @JsonProperty("current_password") @NotNull @Size(max = 1024) String currentPassword,
        @JsonProperty("new_password") @NotNull @Size(max = 1024) String newPassword) {

    /** Passwords must never reach a log. */
    @Override
    public String toString() {
        return "PasswordChangeBody[current_password=redacted, new_password=redacted]";
    }
}
