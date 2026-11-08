package com.swiftdrop.auth.signals;

import com.swiftdrop.auth.token.SecurityEvent;
import com.swiftdrop.auth.user.StoredIdentityEvent;

/** One diary line as the event to sign: shared by push (EventDelivery) and poll (EventPolling). */
final class SetOf {

    private SetOf() {
    }

    static SecurityEvent event(StoredIdentityEvent line) {
        return new SecurityEvent(line.id(), line.userId(), line.version(), line.eventType(), line.data(),
                line.occurredAt());
    }
}
