package com.swiftdrop.auth.account;

import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/** Sends the email-change emails AFTER the request committed, asynchronously; failures stay in the outbox. */
@Component
class EmailChangeListener {

    private final EmailChangeService emailChanges;

    EmailChangeListener(EmailChangeService emailChanges) {
        this.emailChanges = emailChanges;
    }

    @ApplicationModuleListener
    void on(EmailChangeRequested event) {
        emailChanges.sendRequestEmails(event.requestId());
    }

    @ApplicationModuleListener
    void on(EmailChangeConfirmed event) {
        emailChanges.sendConfirmedEmails(event.requestId());
    }
}
