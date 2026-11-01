package com.swiftdrop.auth.common.web;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;

import java.time.Duration;

/**
 * Buckets in this instance's memory: a single instance, tests, and the fallback while Redis is down.
 * Size-limited, so an attacker inventing IPs can't fill the memory; the oldest keys are dropped first.
 */
final class LocalRateLimitStore implements RateLimitStore {

    private static final Duration FORGET_IDLE_KEYS_AFTER = Duration.ofMinutes(15);

    private final Cache<String, Bucket> buckets;

    LocalRateLimitStore(int maxTrackedKeys) {
        this.buckets = Caffeine.newBuilder()
                .maximumSize(maxTrackedKeys)
                .expireAfterAccess(FORGET_IDLE_KEYS_AFTER)
                .build();
    }

    @Override
    public ConsumptionProbe tryConsume(String key, RateLimitProperties.Rule rule) {
        Bucket bucket = buckets.get(key, unused ->
                Bucket.builder().addLimit(RateLimitStore.configurationFor(rule).getBandwidths()[0]).build());
        return bucket.tryConsumeAndReturnRemaining(1);
    }
}
