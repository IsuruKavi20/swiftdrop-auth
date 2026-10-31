package com.swiftdrop.auth.common.web;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResponseTimeFloorTest {

    private static final Duration FLOOR = Duration.ofMillis(300);

    private final ResponseTimeFloor floor = new ResponseTimeFloor(FLOOR);

    @Test
    void fastWorkIsPaddedToTheFloor() {
        long start = System.nanoTime();

        String result = floor.atLeast(() -> "quick");

        assertThat(result).isEqualTo("quick");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(FLOOR);
    }

    @Test
    void failuresArePaddedToo() {
        long start = System.nanoTime();

        assertThatThrownBy(() -> floor.atLeast(() -> {
            throw new IllegalStateException("fails fast");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(FLOOR);
    }

    @Test
    void slowWorkIsNotDelayedFurther() {
        long start = System.nanoTime();

        floor.atLeast(() -> {
            sleep(Duration.ofMillis(400));
            return null;
        });

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(650));
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
