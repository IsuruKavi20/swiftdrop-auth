package com.swiftdrop.auth.session;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code swiftdrop.session.*}: a session ends after {@code idleTimeout} without a refresh, and after
 * {@code absoluteTimeout} since login no matter what.
 */
@ConfigurationProperties("swiftdrop.session")
public record SessionProperties(Duration idleTimeout, Duration absoluteTimeout) {

    private static final Duration MAX_ABSOLUTE = Duration.ofDays(90);

    public SessionProperties {
        if (idleTimeout == null || idleTimeout.isNegative() || idleTimeout.isZero()) {
            throw new IllegalArgumentException("swiftdrop.session.idle-timeout must be positive");
        }
        if (absoluteTimeout == null || absoluteTimeout.compareTo(idleTimeout) < 0
                || absoluteTimeout.compareTo(MAX_ABSOLUTE) > 0) {
            throw new IllegalArgumentException(
                    "swiftdrop.session.absolute-timeout must be between idle-timeout and 90 days");
        }
    }
}
