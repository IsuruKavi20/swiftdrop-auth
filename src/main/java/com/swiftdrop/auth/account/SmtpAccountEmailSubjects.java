package com.swiftdrop.auth.account;

/** Subjects of the account-security emails (also used by tests to find them in the inbox). */
final class SmtpAccountEmailSubjects {

    static final String CONFIRM_NEW_EMAIL = "Confirm your new SwiftDrop email address";
    static final String ADDRESS_ALREADY_USED = "This email address already has a SwiftDrop account";
    static final String CHANGE_REQUESTED = "A change of your SwiftDrop email address was requested";
    static final String EMAIL_CHANGED = "Your SwiftDrop email address was changed";
    static final String PASSWORD_CHANGED = "Your SwiftDrop password was changed";

    private SmtpAccountEmailSubjects() {
    }
}
