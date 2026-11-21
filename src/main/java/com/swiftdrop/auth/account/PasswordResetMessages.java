package com.swiftdrop.auth.account;

/** The one answer to "forgot password", whether or not the email has an account. */
public final class PasswordResetMessages {

    public static final String ACCEPTED =
            "If an account exists for this email, we've sent a link to reset the password.";

    private PasswordResetMessages() {
    }
}
