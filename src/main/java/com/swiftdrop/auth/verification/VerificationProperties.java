package com.swiftdrop.auth.verification;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code swiftdrop.verification.*}: how long a link is valid, and anti-flooding limits per user
 * (no new email within the cooldown, at most {@code maxEmailsPerDay} in 24 hours).
 */
@ConfigurationProperties("swiftdrop.verification")
public record VerificationProperties(Duration tokenTtl, Duration resendCooldown, int maxEmailsPerDay) {

    private static final Duration MAX_TTL = Duration.ofDays(7);

    public VerificationProperties {
        if (tokenTtl == null || tokenTtl.isNegative() || tokenTtl.isZero() || tokenTtl.compareTo(MAX_TTL) > 0) {
            throw new IllegalArgumentException("swiftdrop.verification.token-ttl must be between 1s and 7 days");
        }
        if (resendCooldown == null || resendCooldown.isNegative()) {
            throw new IllegalArgumentException("swiftdrop.verification.resend-cooldown must be zero or positive");
        }
        if (maxEmailsPerDay < 1 || maxEmailsPerDay > 50) {
            throw new IllegalArgumentException("swiftdrop.verification.max-emails-per-day must be between 1 and 50");
        }
    }
}
