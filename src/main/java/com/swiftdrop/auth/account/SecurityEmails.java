package com.swiftdrop.auth.account;

import com.swiftdrop.auth.user.EmailAddress;

import java.net.URI;

/**
 * Port for the account-security emails (email change, later password change and deletion). Business code depends
 * only on this; SMTP today, the notification service later.
 */
interface SecurityEmails {

    /** To the NEW address: the one-time link that confirms it. */
    void sendConfirmNewEmail(EmailAddress to, URI confirmLink);

    /** To the NEW address when it already belongs to an account: no link, and no hint whose account. */
    void sendAddressAlreadyUsed(EmailAddress to);

    /** To the OLD address: a change was requested (new address shown masked). */
    void sendChangeRequested(EmailAddress to, String maskedNewEmail);

    /** To the OLD address after the change: what happened, and the undo link. */
    void sendEmailChanged(EmailAddress to, String maskedNewEmail, URI undoLink);
}
