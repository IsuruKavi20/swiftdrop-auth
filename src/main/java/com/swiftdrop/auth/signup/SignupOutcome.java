package com.swiftdrop.auth.signup;

/**
 * What happened internally. The HTTP response is identical for both (anti-enumeration);
 * the outcome only decides which email to send (Part 6.6).
 */
public enum SignupOutcome {
    ACCOUNT_CREATED,
    EMAIL_ALREADY_REGISTERED
}
