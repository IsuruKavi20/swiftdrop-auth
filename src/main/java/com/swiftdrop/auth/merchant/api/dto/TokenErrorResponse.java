package com.swiftdrop.auth.merchant.api.dto;

/**
 * The OAuth 2.0 error shape (RFC 6749 5.2), which OAuth client libraries expect from a token endpoint,
 * instead of our usual Problem Details.
 */
public record TokenErrorResponse(String error) {
}
