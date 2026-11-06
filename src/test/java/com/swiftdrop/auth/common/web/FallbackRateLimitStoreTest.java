package com.swiftdrop.auth.common.web;

import io.github.bucket4j.ConsumptionProbe;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Redis down: limits keep working per instance instead of failing every login (lesson 16, section 3c). */
class FallbackRateLimitStoreTest {

    private static final RateLimitProperties.Rule LOGIN =
            new RateLimitProperties.Rule("login", "POST", "/api/v1/auth/login", 2);

    private static final RateLimitStore BROKEN = (key, rule) -> {
        throw new IllegalStateException("Redis is down");
    };

    @Test
    void whenTheSharedStoreFailsTheLocalLimitStillApplies() {
        RateLimitStore store = new FallbackRateLimitStore(BROKEN, new LocalRateLimitStore(100));

        assertThat(store.tryConsume("login|203.0.113.7", LOGIN).isConsumed()).isTrue();
        assertThat(store.tryConsume("login|203.0.113.7", LOGIN).isConsumed()).isTrue();
        assertThat(store.tryConsume("login|203.0.113.7", LOGIN).isConsumed()).isFalse();
    }

    @Test
    void theSharedStoreIsUsedWhileItWorks() {
        RateLimitStore alwaysEmpty = (key, rule) -> ConsumptionProbe.rejected(0, 1_000_000_000L, 1_000_000_000L);
        RateLimitStore store = new FallbackRateLimitStore(alwaysEmpty, new LocalRateLimitStore(100));

        assertThat(store.tryConsume("login|203.0.113.7", LOGIN).isConsumed()).isFalse();
    }

    @Test
    void afterAFailureRedisIsSkippedForAFewSecondsThenTriedAgain() {
        java.util.concurrent.atomic.AtomicInteger sharedCalls = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicLong now = new java.util.concurrent.atomic.AtomicLong(0);
        RateLimitStore failing = (key, rule) -> {
            sharedCalls.incrementAndGet();
            throw new IllegalStateException("Redis is down");
        };
        RateLimitStore store = new FallbackRateLimitStore(failing, new LocalRateLimitStore(100), now::get);

        store.tryConsume("login|a", LOGIN);
        store.tryConsume("login|a", LOGIN);   // no second wait for a Redis timeout
        assertThat(sharedCalls).hasValue(1);

        now.addAndGet(FallbackRateLimitStore.SKIP_SHARED_AFTER_FAILURE.toNanos());
        store.tryConsume("login|b", LOGIN);
        assertThat(sharedCalls).hasValue(2);
    }

    @Test
    void localBucketsAreSeparatePerKey() {
        LocalRateLimitStore store = new LocalRateLimitStore(100);
        store.tryConsume("login|a", LOGIN);
        store.tryConsume("login|a", LOGIN);

        assertThat(store.tryConsume("login|a", LOGIN).isConsumed()).isFalse();
        assertThat(store.tryConsume("login|b", LOGIN).isConsumed()).isTrue();
    }

    @Test
    void redisKeysCarryOurPrefix() {
        assertThat(RedisRateLimitStore.redisKey("login|203.0.113.7")).isEqualTo("swiftdrop:rl:login|203.0.113.7");
    }
}
