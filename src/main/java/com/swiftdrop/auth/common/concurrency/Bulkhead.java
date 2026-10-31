package com.swiftdrop.auth.common.concurrency;

import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Caps how many expensive operations run at the same time (like a ship's watertight compartments:
 * one overloaded part can't sink the whole service). When every slot is busy, callers get
 * {@link ServiceBusyException} (503) quickly instead of piling up and exhausting memory.
 */
public class Bulkhead {

    private final Semaphore slots;
    private final Duration maxWait;

    public Bulkhead(int maxConcurrent, Duration maxWait) {
        this.slots = new Semaphore(maxConcurrent, true);
        this.maxWait = maxWait;
    }

    public <T> T call(Supplier<T> work) {
        if (!tryAcquire()) {
            throw new ServiceBusyException();
        }
        try {
            return work.get();
        } finally {
            slots.release();
        }
    }

    private boolean tryAcquire() {
        try {
            return slots.tryAcquire(maxWait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
