package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.signup.AccountRegistered;
import com.swiftdrop.auth.signup.SignupAttemptOnExistingAccount;
import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/**
 * Reacts to signup events AFTER their transaction committed, asynchronously, in a new transaction.
 * Spring Modulith's registry stored each event in the same transaction that published it (outbox):
 * if sending fails here, the publication stays incomplete and is retried.
 */
@Component
class AccountEmailListener {

    private final EmailVerificationService verification;

    AccountEmailListener(EmailVerificationService verification) {
        this.verification = verification;
    }

    @ApplicationModuleListener
    void on(AccountRegistered event) {
        verification.issueVerification(event.userId());
    }

    @ApplicationModuleListener
    void on(SignupAttemptOnExistingAccount event) {
        verification.handleSignupAttemptOnExistingAccount(event.userId());
    }

    @ApplicationModuleListener
    void on(VerificationEmailRequested event) {
        verification.issueVerification(event.userId());
    }
}
