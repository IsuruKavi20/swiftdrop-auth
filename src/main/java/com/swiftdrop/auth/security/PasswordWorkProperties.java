package com.swiftdrop.auth.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Limits on concurrent "password work" (breach check + Argon2), bound from
 * {@code swiftdrop.security.password-work.*}. Worst-case memory = maxConcurrent x Argon2 memory.
 */
@Validated
@ConfigurationProperties("swiftdrop.security.password-work")
public record PasswordWorkProperties(
        @Min(1) @Max(64) int maxConcurrent,
        @NotNull Duration maxWait) {
}
