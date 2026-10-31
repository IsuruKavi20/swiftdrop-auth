package com.swiftdrop.auth.common.concurrency;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class MdcTaskDecoratorTest {

    @AfterEach
    void clear() {
        MDC.clear();
    }

    @Test
    void backgroundTaskSeesTheRequestIdOfTheThreadThatSubmittedIt() throws Exception {
        MDC.put("requestId", "req-123456789");
        AtomicReference<String> seen = new AtomicReference<>();
        Runnable decorated = new MdcTaskDecorator().decorate(() -> seen.set(MDC.get("requestId")));
        MDC.clear();

        CompletableFuture.runAsync(decorated).get();

        assertThat(seen.get()).isEqualTo("req-123456789");
    }

    @Test
    void workerThreadIsCleanedUpAfterwards() throws Exception {
        MDC.put("requestId", "req-123456789");
        Runnable decorated = new MdcTaskDecorator().decorate(() -> { });
        AtomicReference<String> afterwards = new AtomicReference<>("not-checked");

        Thread worker = Thread.ofPlatform().start(() -> {
            decorated.run();
            afterwards.set(MDC.get("requestId"));
        });
        worker.join();

        assertThat(afterwards.get()).isNull();
    }
}
