package com.swiftdrop.auth.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Argon2id cost settings, bound from {@code swiftdrop.security.password.*}.
 * The app refuses to start if a value is weaker than OWASP's minimum (fail fast).
 * Tune memory/iterations so one hash takes about 250 ms on the production server.
 */
@Validated
@ConfigurationProperties("swiftdrop.security.password")
public record PasswordHashingProperties(
        @Min(16) @Max(64) int saltLengthBytes,
        @Min(32) @Max(64) int hashLengthBytes,
        @Min(1) @Max(16) int parallelism,
        // Upper bound stops a config mistake from exhausting server memory (each hash uses this much)
        @Min(19_456) @Max(262_144) int memoryKb,
        // OWASP's 19 MiB minimum assumes at least 2 iterations
        @Min(2) @Max(10) int iterations) {
}
