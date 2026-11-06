package com.swiftdrop.auth.common.web;

import io.github.bucket4j.ConsumptionProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Redis first; if Redis fails, this instance's own buckets ("fail open to local limits", lesson 16, 3c).
 * Login stays up with weaker limits for a while; the per-account lockout in Postgres still stops guessing.
 * After a failure Redis is skipped for a few seconds (a small circuit breaker): during an outage requests go
 * straight to the local buckets instead of each waiting for a Redis timeout. The warning is logged at most
 * once a minute, so an outage can't flood the logs.
 */
final class FallbackRateLimitStore implements RateLimitStore, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(FallbackRateLimitStore.class);
    private static final long WARN_EVERY_NANOS = Duration.ofMinutes(1).toNanos();
    static final Duration SKIP_SHARED_AFTER_FAILURE = Duration.ofSeconds(5);

    private final RateLimitStore shared;
    private final RateLimitStore local;
    private final LongSupplier nanoClock;
    private final AtomicLong lastWarning;
    private final AtomicLong sharedSkippedUntil;

    FallbackRateLimitStore(RateLimitStore shared, RateLimitStore local) {
        this(shared, local, System::nanoTime);
    }

    FallbackRateLimitStore(RateLimitStore shared, RateLimitStore local, LongSupplier nanoClock) {
        this.shared = shared;
        this.local = local;
        this.nanoClock = nanoClock;
        long now = nanoClock.getAsLong();
        this.lastWarning = new AtomicLong(now - WARN_EVERY_NANOS);
        this.sharedSkippedUntil = new AtomicLong(now);
    }

    @Override
    public ConsumptionProbe tryConsume(String key, RateLimitProperties.Rule rule) {
        if (nanoClock.getAsLong() - sharedSkippedUntil.get() < 0) {
            return local.tryConsume(key, rule);
        }
        try {
            return shared.tryConsume(key, rule);
        } catch (RuntimeException sharedStoreFailed) {
            sharedSkippedUntil.set(nanoClock.getAsLong() + SKIP_SHARED_AFTER_FAILURE.toNanos());
            warnOccasionally(sharedStoreFailed);
            return local.tryConsume(key, rule);
        }
    }

    private void warnOccasionally(RuntimeException cause) {
        long now = nanoClock.getAsLong();
        long last = lastWarning.get();
        if (now - last >= WARN_EVERY_NANOS && lastWarning.compareAndSet(last, now)) {
            log.warn("Shared rate limits unavailable, using this instance's own limits: {}", cause.toString());
        }
    }

    /** Spring calls this on shutdown (the bean's inferred destroy method): closes the Redis connection. */
    @Override
    public void close() throws Exception {
        if (shared instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }
}
