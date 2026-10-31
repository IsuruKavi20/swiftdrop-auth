package com.swiftdrop.auth.merchant.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** A label so the merchant can tell their clients apart ("warehouse", "web shop"). */
public record CreateClientRequest(@NotBlank @Size(max = 60) @Pattern(regexp = "^[A-Za-z0-9 _.-]+$") String name) {
}
