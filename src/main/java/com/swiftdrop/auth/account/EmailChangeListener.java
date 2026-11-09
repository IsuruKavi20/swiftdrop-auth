package com.swiftdrop.auth.account;

import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/** Sends the account-security emails AFTER the change committed, asynchronously; failures stay in the outbox. */
@Component
class EmailChangeListener {

    private final EmailChangeService emailChanges;
    private final PasswordChangeService passwordChanges;

    EmailChangeListener(EmailChangeService emailChanges, PasswordChangeService passwordChanges) {
        this.emailChanges = emailChanges;
        this.passwordChanges = passwordChanges;
    }

    @ApplicationModuleListener
    void on(EmailChangeRequested event) {
        emailChanges.sendRequestEmails(event.requestId(), event.frontendId());
    }

    @ApplicationModuleListener
    void on(EmailChangeConfirmed event) {
        emailChanges.sendConfirmedEmails(event.requestId(), event.frontendId());
    }

    @ApplicationModuleListener
    void on(PasswordChanged event) {
        passwordChanges.sendPasswordChangedEmail(event.userId());
    }
}
