package com.swiftdrop.auth.merchant.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** "Become a merchant": only what an admin needs to decide. The website, if given, must be https. */
public record MerchantApplicationRequest(
        @NotBlank @Size(max = 120) String businessName,
        @NotBlank @Size(max = 50) @Pattern(regexp = "^[A-Za-z0-9 /-]+$") String registrationNumber,
        @Size(max = 255) @Pattern(regexp = "^https://[^\\s<>\"]+$") String website) {
}
