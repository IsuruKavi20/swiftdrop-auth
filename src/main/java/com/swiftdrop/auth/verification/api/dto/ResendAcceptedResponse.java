package com.swiftdrop.auth.verification.api.dto;

/** Same answer for every address, registered or not. */
public record ResendAcceptedResponse(String message) {

    public static final ResendAcceptedResponse ACCEPTED = new ResendAcceptedResponse(
            "If this address has an account waiting for verification, we've sent a new link.");
}
