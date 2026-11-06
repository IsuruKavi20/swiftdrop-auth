package com.swiftdrop.auth.common.web;

import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;

import java.time.Duration;

/** Where the token buckets live: this instance's memory, or Redis shared by every instance (lesson 16). */
@FunctionalInterface
interface RateLimitStore {

    Duration WINDOW = Duration.ofMinutes(1);

    /** Takes one token from the bucket for {@code key}, creating it for {@code rule} when it doesn't exist yet. */
    ConsumptionProbe tryConsume(String key, RateLimitProperties.Rule rule);

    // Greedy refill: tokens come back smoothly over the minute, not all at once at the end
    static BucketConfiguration configurationFor(RateLimitProperties.Rule rule) {
        return BucketConfiguration.builder()
                .addLimit(limit -> limit.capacity(rule.perMinute()).refillGreedy(rule.perMinute(), WINDOW))
                .build();
    }
}
