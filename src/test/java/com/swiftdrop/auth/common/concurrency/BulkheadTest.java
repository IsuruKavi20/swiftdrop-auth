package com.swiftdrop.auth.common.concurrency;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BulkheadTest {

    @Test
    void runsWorkWhenASlotIsFree() {
        Bulkhead bulkhead = new Bulkhead(1, Duration.ZERO);

        assertThat(bulkhead.call(() -> "done")).isEqualTo("done");
    }

    @Test
    void rejectsImmediatelyWhenAllSlotsAreBusyAndFreesTheSlotAfterwards() throws Exception {
        Bulkhead bulkhead = new Bulkhead(1, Duration.ofMillis(50));
        CountDownLatch slotTaken = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        try (ExecutorService other = Executors.newSingleThreadExecutor()) {
            other.submit(() -> bulkhead.call(() -> {
                slotTaken.countDown();
                await(release);
                return null;
            }));
            assertThat(slotTaken.await(5, TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> bulkhead.call(() -> "second"))
                    .isInstanceOf(ServiceBusyException.class);

            release.countDown();
        }
        assertThat(bulkhead.call(() -> "after release")).isEqualTo("after release");
    }

    @Test
    void slotIsReleasedEvenWhenTheWorkFails() {
        Bulkhead bulkhead = new Bulkhead(1, Duration.ZERO);

        assertThatThrownBy(() -> bulkhead.call(() -> {
            throw new IllegalStateException("boom");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(bulkhead.call(() -> "still usable")).isEqualTo("still usable");
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
