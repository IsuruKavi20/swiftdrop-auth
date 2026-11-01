package com.swiftdrop.auth.common.web;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;
import java.util.Locale;

/**
 * {@code swiftdrop.rate-limit.*}: per-IP limits for the public endpoints (deep dive 26). Every number is
 * configuration, validated at startup. {@code maxTrackedKeys} bounds memory: an attacker inventing IPs can't
 * fill it, the oldest keys are dropped first. {@code store}: {@code local} = this instance's memory,
 * {@code redis} = shared by every instance, falling back to local while Redis is down (lesson 16).
 */
@ConfigurationProperties("swiftdrop.rate-limit")
public record RateLimitProperties(boolean enabled, @DefaultValue("100000") int maxTrackedKeys, List<Rule> rules,
                                  @DefaultValue("local") Store store) {

    private static final int MAX_PER_MINUTE = 10_000;

    public enum Store { LOCAL, REDIS }

    @ConstructorBinding
    public RateLimitProperties {
        if (maxTrackedKeys < 1) {
            throw new IllegalArgumentException("swiftdrop.rate-limit.max-tracked-keys must be at least 1");
        }
        rules = rules == null ? List.of() : List.copyOf(rules);
        store = store == null ? Store.LOCAL : store;
    }

    /** In-memory buckets (unit tests). */
    public RateLimitProperties(boolean enabled, int maxTrackedKeys, List<Rule> rules) {
        this(enabled, maxTrackedKeys, rules, Store.LOCAL);
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
