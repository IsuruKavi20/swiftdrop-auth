package com.swiftdrop.auth.account.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Body of POST /me/email-change. Coarse limits only; EmailAddress and the password check do the real work. */
public record EmailChangeBody(
        @JsonProperty("new_email") @NotBlank @Size(max = 320) String newEmail,
        @JsonProperty("current_password") @NotNull @Size(max = 1024) String currentPassword) {

    /** The email and password must never reach a log. */
    @Override
    public String toString() {
        return "EmailChangeBody[new_email=redacted, current_password=redacted]";
    }
}
