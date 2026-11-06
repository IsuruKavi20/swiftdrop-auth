package com.swiftdrop.auth.account.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Just the current password, to confirm a sensitive action (account deletion). */
public record CurrentPasswordBody(@JsonProperty("current_password") @NotNull @Size(max = 1024) String currentPassword) {

    /** The password must never reach a log. */
    @Override
    public String toString() {
        return "CurrentPasswordBody[current_password=redacted]";
    }
}
