package com.swiftdrop.auth.common.web;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;
import java.util.Locale;

/**
 * {@code swiftdrop.rate-limit.*}: per-IP limits for the public endpoints (deep dive 26). Every number is
 * configuration, validated at startup. {@code maxTrackedKeys} bounds memory: an attacker inventing IPs can't
 * fill it, the oldest keys are dropped first.
 */
@ConfigurationProperties("swiftdrop.rate-limit")
public record RateLimitProperties(boolean enabled, @DefaultValue("100000") int maxTrackedKeys, List<Rule> rules) {

    private static final int MAX_PER_MINUTE = 10_000;

    public RateLimitProperties {
        if (maxTrackedKeys < 1) {
            throw new IllegalArgumentException("swiftdrop.rate-limit.max-tracked-keys must be at least 1");
        }
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    /** One limited endpoint: {@code perMinute} requests per client IP per minute, for exactly this method + path. */
    public record Rule(String name, String method, String path, int perMinute) {

        public Rule {
            if (name == null || name.isBlank() || method == null || method.isBlank()) {
                throw new IllegalArgumentException("swiftdrop.rate-limit rules need a name and a method");
            }
            if (path == null || !path.startsWith("/")) {
                throw new IllegalArgumentException("swiftdrop.rate-limit rule '" + name + "': path must start with /");
            }
            if (perMinute < 1 || perMinute > MAX_PER_MINUTE) {
                throw new IllegalArgumentException(
                        "swiftdrop.rate-limit rule '" + name + "': per-minute must be between 1 and " + MAX_PER_MINUTE);
            }
            method = method.toUpperCase(Locale.ROOT);
        }

        boolean matches(String requestMethod, String requestPath) {
            return method.equalsIgnoreCase(requestMethod) && path.equals(requestPath);
        }
    }
}
