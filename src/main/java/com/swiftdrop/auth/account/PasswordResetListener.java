package com.swiftdrop.auth.account;

import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/** Sends the reset link AFTER the request committed, asynchronously; failures stay in the outbox and are retried. */
@Component
class PasswordResetListener {

    private final PasswordResetService resets;

    PasswordResetListener(PasswordResetService resets) {
        this.resets = resets;
    }

    @ApplicationModuleListener
    void on(PasswordResetRequested event) {
        resets.issueLink(event.userId(), event.frontendId());
    }
}
