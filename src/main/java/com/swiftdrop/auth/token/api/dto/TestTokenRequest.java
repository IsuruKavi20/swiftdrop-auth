package com.swiftdrop.auth.token.api.dto;

import com.swiftdrop.auth.user.RoleName;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

/**
 * @param roles  1-5 of the real role names (an unknown name fails JSON parsing → 400)
 * @param userId optional: a fixed ID lets tests use "courier A" and "courier B"; random when missing
 */
public record TestTokenRequest(
        @NotEmpty @Size(max = 5) List<@NotNull RoleName> roles,
        UUID userId) {
}
