package com.swiftdrop.auth.account.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of the email-change link endpoints: the one-time token from the emailed link's #fragment. */
public record LinkTokenBody(@NotBlank @Size(max = 64) String token) {

    /** The token is a credential: never in a log. */
    @Override
    public String toString() {
        return "LinkTokenBody[token=redacted]";
    }
}
