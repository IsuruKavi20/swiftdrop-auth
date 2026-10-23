package com.swiftdrop.auth.signup.api.dto;

/** The one and only signup answer, whether or not the email already had an account. */
public record SignupAcceptedResponse(String message) {

    public static final SignupAcceptedResponse ACCEPTED = new SignupAcceptedResponse(
            "If this address can be used, we've sent a verification email. Check your inbox.");
}
