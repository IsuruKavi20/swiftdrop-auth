package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.user.EmailAddress;

import java.net.URI;

/**
 * Port for the account emails this service needs. Business code depends only on this interface; the
 * technology (SMTP today, Module 5's notification service later) plugs in behind it.
 */
public interface AccountEmailSender {

    void sendVerification(EmailAddress to, URI verificationLink);

    void sendAlreadyRegistered(EmailAddress to, URI loginLink);
}
