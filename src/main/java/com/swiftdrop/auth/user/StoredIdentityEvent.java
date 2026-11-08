package com.swiftdrop.auth.user;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** One line of the identity_events diary, as read back for delivery (identity step 6). */
public record StoredIdentityEvent(UUID id, long seq, UUID userId, long version, String eventType,
                                  Map<String, Object> data, Instant occurredAt) {

    /** The data can hold personal data: never print it. */
    @Override
    public String toString() {
        return "StoredIdentityEvent[id=" + id + ", seq=" + seq + ", type=" + eventType + "]";
    }
}
