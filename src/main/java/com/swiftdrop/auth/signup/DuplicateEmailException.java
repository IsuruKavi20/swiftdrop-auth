package com.swiftdrop.auth.signup;

/** Internal signal between UserRegistrar and SignupService. Never reaches a client. */
class DuplicateEmailException extends RuntimeException {

    DuplicateEmailException() {
        super("Email already registered", null, false, false);
    }
}
