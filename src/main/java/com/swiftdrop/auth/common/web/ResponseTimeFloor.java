package com.swiftdrop.auth.common.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Anti-enumeration: endpoints whose answer must not reveal whether an account exists never respond
 * faster than a fixed minimum, so small differences in work (an extra DB write, a skipped query) can't
 * be measured. With virtual threads, the waiting costs almost nothing.
 */
@Component
public class ResponseTimeFloor {

    private final Duration minimum;

    public ResponseTimeFloor(@Value("${swiftdrop.web.anti-enumeration-min-duration:400ms}") Duration minimum) {
        this.minimum = minimum;
    }

    public <T> T atLeast(Supplier<T> work) {
        long start = System.nanoTime();
        try {
            return work.get();
        } finally {
            waitForTheRest(start);
        }
    }

    public void atLeast(Runnable work) {
        atLeast(() -> {
            work.run();
            return null;
        });
    }

    private void waitForTheRest(long start) {
        long remainingNanos = minimum.toNanos() - (System.nanoTime() - start);
        if (remainingNanos <= 0) {
            return;
        }
        try {
            Thread.sleep(Duration.ofNanos(remainingNanos));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
