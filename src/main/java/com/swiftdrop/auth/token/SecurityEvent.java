package com.swiftdrop.auth.token;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * One identity event ready to be signed (identity step 6b): a line of the {@code identity_events} diary.
 *
 * @param id         becomes the SET's {@code jti}
 * @param version    the person's event number (receivers ignore older or repeated numbers)
 * @param eventType  the event type URI (RISC, CAEP or SwiftDrop's own)
 * @param data       what changed (never secrets)
 * @param occurredAt becomes {@code toe}, the time of the event
 */
public record SecurityEvent(UUID id, UUID userId, long version, String eventType, Map<String, Object> data,
                            Instant occurredAt) {

    /** The data can hold personal data (e.g. a new name): never print it. */
    @Override
    public String toString() {
        return "SecurityEvent[id=" + id + ", type=" + eventType + ", version=" + version + "]";
    }
}
