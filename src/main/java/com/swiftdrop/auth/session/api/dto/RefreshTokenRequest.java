package com.swiftdrop.auth.session.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of /refresh and /logout. Named like OAuth's refresh_token parameter (RFC 6749 6). */
public record RefreshTokenRequest(
        @JsonProperty("refresh_token") @NotBlank @Size(max = 64) String refreshToken) {

    @Override
    public String toString() {
        return "RefreshTokenRequest[refreshToken=redacted]";
    }
}
