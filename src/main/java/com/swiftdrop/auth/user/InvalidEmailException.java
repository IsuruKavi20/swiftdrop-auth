package com.swiftdrop.auth.user;

public class InvalidEmailException extends RuntimeException {

    public InvalidEmailException() {
        // Never include the address itself: it is personal data and must not reach logs
        super("Email address is not valid");
    }
}
