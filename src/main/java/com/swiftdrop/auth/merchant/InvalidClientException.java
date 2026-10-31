package com.swiftdrop.auth.merchant;

/**
 * RFC 6749 5.2 "invalid_client": unknown client, wrong secret, revoked, or merchant not allowed any more.
 * One answer for all, so nothing can be learned from it.
 */
public class InvalidClientException extends RuntimeException {

    public InvalidClientException() {
        super("invalid_client");
    }
}
